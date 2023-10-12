package isuports

import (
	"context"
	"database/sql"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const (
	tenantDBSchemaFilePath = "../sql/tenant/10_schema.sql"
	initializeScript       = "../sql/init.sh"
	cookieName             = "isuports_session"

	RoleAdmin     = "admin"
	RoleOrganizer = "organizer"
	RolePlayer    = "player"
	RoleNone      = "none"
)

type visitMapStruct struct {
	data  map[string]map[string]struct{}
	mutex sync.RWMutex
}

func (v *visitMapStruct) get(competitionID string) []string {
	v.mutex.RLock()
	defer v.mutex.RUnlock()
	var playerIDs []string
	for playerID := range v.data[competitionID] {
		playerIDs = append(playerIDs, playerID)
	}
	return playerIDs
}

func (v *visitMapStruct) set(competitionID string, playerID string) {
	v.mutex.Lock()
	defer v.mutex.Unlock()
	_, ok := v.data[competitionID]
	if !ok {
		v.data[competitionID] = map[string]struct{}{}
	}
	v.data[competitionID][playerID] = struct{}{}
}

type competitionID2TitleStruct struct {
	data  map[string]string
	mutex sync.RWMutex
}

func (c *competitionID2TitleStruct) get(competitionID string) string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.data[competitionID]
}

func (c *competitionID2TitleStruct) set(competitionID string, title string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.data[competitionID] = title
}

type playerID2NameStruct struct {
	data  map[string]string
	mutex sync.RWMutex
}

func (p *playerID2NameStruct) get(playerID string) string {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.data[playerID]
}

func (p *playerID2NameStruct) set(playerID string, name string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.data[playerID] = name
}

var (
	// 正しいテナント名の正規表現
	tenantNameRegexp = regexp.MustCompile(`^[a-z][a-z0-9-]{0,61}[a-z0-9]$`)

	adminDB *sqlx.DB
	/*
		tenantテーブル : 10.0.0.182
		competitionテーブル, playerテーブル, player_scoreテーブルはtenant_idが奇数なら10.0.0.182, 偶数なら10.0.0.137
	*/
	DB1Host   = "10.0.0.182"
	DB2Host   = "10.0.0.137"
	tenantDBs []*sqlx.DB // tenantDBs[0]が10.0.0.182, tenantDBs[1]が10.0.0.137

	sqliteDriverName = "sqlite3"

	visitMap = visitMapStruct{
		data: map[string]map[string]struct{}{},
	}
	competitionID2Title = competitionID2TitleStruct{
		data: map[string]string{},
	}
	playerID2Name = playerID2NameStruct{
		data: map[string]string{},
	}

	// mutex
	bulkInsertMutex sync.Mutex

	globalID int64 = 2678400000
)

// 環境変数を取得する、なければデフォルト値を返す
func getEnv(key string, defaultValue string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultValue
}

// 管理用DBに接続する
func connectAdminDB(DBHost string) (*sqlx.DB, error) {
	config := mysql.NewConfig()
	config.Net = "tcp"
	config.Addr = DBHost + ":" + getEnv("ISUCON_DB_PORT", "3306")
	config.User = getEnv("ISUCON_DB_USER", "isucon")
	config.Passwd = getEnv("ISUCON_DB_PASSWORD", "isucon")
	config.DBName = getEnv("ISUCON_DB_NAME", "isuports")
	config.ParseTime = true
	dsn := config.FormatDSN()
	return sqlx.Open("mysql", dsn)
}

func connectTenantMySQLDB(DBHost string) (*sqlx.DB, error) {
	config := mysql.NewConfig()
	config.Net = "tcp"
	config.Addr = DBHost + ":" + getEnv("ISUCON_DB_PORT", "3306")
	config.User = getEnv("ISUCON_DB_USER", "isucon")
	config.Passwd = getEnv("ISUCON_DB_PASSWORD", "isucon")
	config.DBName = "isuports_tenant"
	config.ParseTime = true
	dsn := config.FormatDSN()
	return sqlx.Open("mysql", dsn)
}

// テナントDBのパスを返す
func tenantDBPath(id int64) string {
	tenantDBDir := getEnv("ISUCON_TENANT_DB_DIR", "../tenant_db")
	return filepath.Join(tenantDBDir, fmt.Sprintf("%d.db", id))
}

// テナントDBに接続する
// func connectToTenantDB(id int64) (*sqlx.DB, error) {
// 	p := tenantDBPath(id)
// 	db, err := sqlx.Open(sqliteDriverName, fmt.Sprintf("file:%s?mode=rw", p))
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to open tenant DB: %w", err)
// 	}
// 	return db, nil
// }

// テナントDBを新規に作成する
// func createTenantDB(id int64) error {
// 	p := tenantDBPath(id)
//
// 	cmd := exec.Command("sh", "-c", fmt.Sprintf("sqlite3 %s < %s", p, tenantDBSchemaFilePath))
// 	if out, err := cmd.CombinedOutput(); err != nil {
// 		return fmt.Errorf("failed to exec sqlite3 %s < %s, out=%s: %w", p, tenantDBSchemaFilePath, string(out), err)
// 	}
// 	return nil
// }

// システム全体で一意なIDを生成する
func dispenseID(ctx context.Context) (string, error) {
	// var id int64
	// var lastErr error
	// for i := 0; i < 100; i++ {
	// 	var ret sql.Result
	// 	ret, err := adminDB.ExecContext(ctx, "REPLACE INTO id_generator (stub) VALUES (?);", "a")
	// 	if err != nil {
	// 		if merr, ok := err.(*mysql.MySQLError); ok && merr.Number == 1213 { // deadlock
	// 			lastErr = fmt.Errorf("error REPLACE INTO id_generator: %w", err)
	// 			continue
	// 		}
	// 		return "", fmt.Errorf("error REPLACE INTO id_generator: %w", err)
	// 	}
	// 	id, err = ret.LastInsertId()
	// 	if err != nil {
	// 		return "", fmt.Errorf("error ret.LastInsertId: %w", err)
	// 	}
	// 	break
	// }
	// if id != 0 {
	// 	return fmt.Sprintf("%x", id), nil
	// }
	// return "", lastErr
	atomic.AddInt64(&globalID, 1)
	return fmt.Sprintf("%x", globalID), nil
}

// 全APIにCache-Control: privateを設定する
func SetCacheControlPrivate(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		c.Response().Header().Set(echo.HeaderCacheControl, "private")
		return next(c)
	}
}

// Run は cmd/isuports/main.go から呼ばれるエントリーポイントです
func Run() {
	if getEnv("PPROF", "0") == "1" {
		go func() {
			http.ListenAndServe("localhost:6060", nil)
		}()
	}

	e := echo.New()
	e.Debug = true
	e.Logger.SetLevel(log.DEBUG)

	var (
		sqlLogger io.Closer
		err       error
	)
	// sqliteのクエリログを出力する設定
	// 環境変数 ISUCON_SQLITE_TRACE_FILE を設定すると、そのファイルにクエリログをJSON形式で出力する
	// 未設定なら出力しない
	// sqltrace.go を参照
	sqliteDriverName, sqlLogger, err = initializeSQLLogger()
	if err != nil {
		e.Logger.Panicf("error initializeSQLLogger: %s", err)
	}
	defer sqlLogger.Close()

	// e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(SetCacheControlPrivate)

	// SaaS管理者向けAPI
	e.POST("/api/admin/tenants/add", tenantsAddHandler)
	e.GET("/api/admin/tenants/billing", tenantsBillingHandler)

	// テナント管理者向けAPI - 参加者追加、一覧、失格
	e.GET("/api/organizer/players", playersListHandler)
	e.POST("/api/organizer/players/add", playersAddHandler)
	e.POST("/api/organizer/player/:player_id/disqualified", playerDisqualifiedHandler)

	// テナント管理者向けAPI - 大会管理
	e.POST("/api/organizer/competitions/add", competitionsAddHandler)
	e.POST("/api/organizer/competition/:competition_id/finish", competitionFinishHandler)
	e.POST("/api/organizer/competition/:competition_id/score", competitionScoreHandler)
	e.GET("/api/organizer/billing", billingHandler)
	e.GET("/api/organizer/competitions", organizerCompetitionsHandler)

	// 参加者向けAPI
	e.GET("/api/player/player/:player_id", playerHandler)
	e.GET("/api/player/competition/:competition_id/ranking", competitionRankingHandler)
	e.GET("/api/player/competitions", playerCompetitionsHandler)

	// 全ロール及び未認証でも使えるhandler
	e.GET("/api/me", meHandler)

	// ベンチマーカー向けAPI
	e.POST("/initialize", initializeHandler)

	e.HTTPErrorHandler = errorResponseHandler

	adminDB, err = connectAdminDB(DB1Host)
	if err != nil {
		e.Logger.Fatalf("failed to connect db: %v", err)
		return
	}
	adminDB.SetMaxOpenConns(70)
	defer adminDB.Close()

	tenantDB1, err := connectTenantMySQLDB(DB1Host)
	if err != nil {
		e.Logger.Fatalf("failed to connect db: %v", err)
		return
	}
	tenantDB1.SetMaxOpenConns(100)
	defer tenantDB1.Close()

	tenantDB2, err := connectTenantMySQLDB(DB2Host)
	if err != nil {
		e.Logger.Fatalf("failed to connect db: %v", err)
		return
	}
	tenantDB2.SetMaxOpenConns(120)
	defer tenantDB2.Close()

	tenantDBs = append(tenantDBs, tenantDB1, tenantDB2)

	port := getEnv("SERVER_APP_PORT", "3000")
	e.Logger.Infof("starting isuports server on : %s ...", port)
	serverPort := fmt.Sprintf(":%s", port)
	e.Logger.Fatal(e.Start(serverPort))
}

// エラー処理関数
func errorResponseHandler(err error, c echo.Context) {
	c.Logger().Errorf("error at %s: %s", c.Path(), err.Error())
	var he *echo.HTTPError
	if errors.As(err, &he) {
		c.JSON(he.Code, FailureResult{
			Status: false,
		})
		return
	}
	c.JSON(http.StatusInternalServerError, FailureResult{
		Status: false,
	})
}

type SuccessResult struct {
	Status bool `json:"status"`
	Data   any  `json:"data,omitempty"`
}

type FailureResult struct {
	Status  bool   `json:"status"`
	Message string `json:"message"`
}

// アクセスしてきた人の情報
type Viewer struct {
	role       string
	playerID   string
	tenantName string
	tenantID   int64
}

// リクエストヘッダをパースしてViewerを返す
func parseViewer(c echo.Context) (*Viewer, error) {
	cookie, err := c.Request().Cookie(cookieName)
	if err != nil {
		return nil, echo.NewHTTPError(
			http.StatusUnauthorized,
			fmt.Sprintf("cookie %s is not found", cookieName),
		)
	}
	tokenStr := cookie.Value

	keyFilename := getEnv("ISUCON_JWT_KEY_FILE", "../public.pem")
	keysrc, err := os.ReadFile(keyFilename)
	if err != nil {
		return nil, fmt.Errorf("error os.ReadFile: keyFilename=%s: %w", keyFilename, err)
	}
	key, _, err := jwk.DecodePEM(keysrc)
	if err != nil {
		return nil, fmt.Errorf("error jwk.DecodePEM: %w", err)
	}

	token, err := jwt.Parse(
		[]byte(tokenStr),
		jwt.WithKey(jwa.RS256, key),
	)
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusUnauthorized, fmt.Errorf("error jwt.Parse: %s", err.Error()))
	}
	if token.Subject() == "" {
		return nil, echo.NewHTTPError(
			http.StatusUnauthorized,
			fmt.Sprintf("invalid token: subject is not found in token: %s", tokenStr),
		)
	}

	var role string
	tr, ok := token.Get("role")
	if !ok {
		return nil, echo.NewHTTPError(
			http.StatusUnauthorized,
			fmt.Sprintf("invalid token: role is not found: %s", tokenStr),
		)
	}
	switch tr {
	case RoleAdmin, RoleOrganizer, RolePlayer:
		role = tr.(string)
	default:
		return nil, echo.NewHTTPError(
			http.StatusUnauthorized,
			fmt.Sprintf("invalid token: invalid role: %s", tokenStr),
		)
	}
	// aud は1要素でテナント名がはいっている
	aud := token.Audience()
	if len(aud) != 1 {
		return nil, echo.NewHTTPError(
			http.StatusUnauthorized,
			fmt.Sprintf("invalid token: aud field is few or too much: %s", tokenStr),
		)
	}
	tenant, err := retrieveTenantRowFromHeader(c)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, echo.NewHTTPError(http.StatusUnauthorized, "tenant not found")
		}
		return nil, fmt.Errorf("error retrieveTenantRowFromHeader at parseViewer: %w", err)
	}
	if tenant.Name == "admin" && role != RoleAdmin {
		return nil, echo.NewHTTPError(http.StatusUnauthorized, "tenant not found")
	}

	if tenant.Name != aud[0] {
		return nil, echo.NewHTTPError(
			http.StatusUnauthorized,
			fmt.Sprintf("invalid token: tenant name is not match with %s: %s", c.Request().Host, tokenStr),
		)
	}

	v := &Viewer{
		role:       role,
		playerID:   token.Subject(),
		tenantName: tenant.Name,
		tenantID:   tenant.ID,
	}
	return v, nil
}

func retrieveTenantRowFromHeader(c echo.Context) (*TenantRow, error) {
	// JWTに入っているテナント名とHostヘッダのテナント名が一致しているか確認
	baseHost := getEnv("ISUCON_BASE_HOSTNAME", ".t.isucon.local")
	tenantName := strings.TrimSuffix(c.Request().Host, baseHost)

	// SaaS管理者用ドメイン
	if tenantName == "admin" {
		return &TenantRow{
			Name:        "admin",
			DisplayName: "admin",
		}, nil
	}

	// テナントの存在確認
	var tenant TenantRow
	if err := adminDB.GetContext(
		context.Background(),
		&tenant,
		"SELECT * FROM tenant WHERE name = ?",
		tenantName,
	); err != nil {
		return nil, fmt.Errorf("failed to Select tenant: name=%s, %w", tenantName, err)
	}
	return &tenant, nil
}

type TenantRow struct {
	ID          int64  `db:"id"`
	Name        string `db:"name"`
	DisplayName string `db:"display_name"`
	CreatedAt   int64  `db:"created_at"`
	UpdatedAt   int64  `db:"updated_at"`
}

type dbOrTx interface {
	GetContext(ctx context.Context, dest interface{}, query string, args ...interface{}) error
	SelectContext(ctx context.Context, dest interface{}, query string, args ...interface{}) error
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
}

type PlayerRow struct {
	TenantID       int64  `db:"tenant_id"`
	ID             string `db:"id"`
	DisplayName    string `db:"display_name"`
	IsDisqualified bool   `db:"is_disqualified"`
	CreatedAt      int64  `db:"created_at"`
	UpdatedAt      int64  `db:"updated_at"`
}

// 参加者を取得する
func retrievePlayer(ctx context.Context, tenantDB dbOrTx, id string) (*PlayerRow, error) {
	var p PlayerRow
	if err := tenantDB.GetContext(ctx, &p, "SELECT * FROM player WHERE id = ?", id); err != nil {
		return nil, fmt.Errorf("error Select player: id=%s, %w", id, err)
	}
	return &p, nil
}

// 参加者を認可する
// 参加者向けAPIで呼ばれる
func authorizePlayer(ctx context.Context, tenantDB dbOrTx, id string) error {
	player, err := retrievePlayer(ctx, tenantDB, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return echo.NewHTTPError(http.StatusUnauthorized, "player not found")
		}
		return fmt.Errorf("error retrievePlayer from viewer: %w", err)
	}
	if player.IsDisqualified {
		return echo.NewHTTPError(http.StatusForbidden, "player is disqualified")
	}
	return nil
}

type CompetitionRow struct {
	TenantID   int64         `db:"tenant_id"`
	ID         string        `db:"id"`
	Title      string        `db:"title"`
	FinishedAt sql.NullInt64 `db:"finished_at"`
	CreatedAt  int64         `db:"created_at"`
	UpdatedAt  int64         `db:"updated_at"`
}

// 大会を取得する
func retrieveCompetition(ctx context.Context, tenantDB dbOrTx, id string) (*CompetitionRow, error) {
	var c CompetitionRow
	if err := tenantDB.GetContext(ctx, &c, "SELECT * FROM competition WHERE id = ?", id); err != nil {
		return nil, fmt.Errorf("error Select competition: id=%s, %w", id, err)
	}
	return &c, nil
}

type PlayerScoreRow struct {
	TenantID      int64  `db:"tenant_id"`
	ID            string `db:"id"`
	PlayerID      string `db:"player_id"`
	CompetitionID string `db:"competition_id"`
	Score         int64  `db:"score"`
	RowNum        int64  `db:"row_num"`
	CreatedAt     int64  `db:"created_at"`
	UpdatedAt     int64  `db:"updated_at"`
}

// 排他ロックのためのファイル名を生成する
// func lockFilePath(id int64) string {
// 	tenantDBDir := getEnv("ISUCON_TENANT_DB_DIR", "../tenant_db")
// 	return filepath.Join(tenantDBDir, fmt.Sprintf("%d.lock", id))
// }

// 排他ロックする
// func flockByTenantID(tenantID int64) (io.Closer, error) {
// 	p := lockFilePath(tenantID)

// 	fl := flock.New(p)
// 	if err := fl.Lock(); err != nil {
// 		return nil, fmt.Errorf("error flock.Lock: path=%s, %w", p, err)
// 	}
// 	return fl, nil
// }

type TenantsAddHandlerResult struct {
	Tenant TenantWithBilling `json:"tenant"`
}

// SasS管理者用API
// テナントを追加する
// POST /api/admin/tenants/add
func tenantsAddHandler(c echo.Context) error {
	v, err := parseViewer(c)
	if err != nil {
		return fmt.Errorf("error parseViewer: %w", err)
	}
	if v.tenantName != "admin" {
		// admin: SaaS管理者用の特別なテナント名
		return echo.NewHTTPError(
			http.StatusNotFound,
			fmt.Sprintf("%s has not this API", v.tenantName),
		)
	}
	if v.role != RoleAdmin {
		return echo.NewHTTPError(http.StatusForbidden, "admin role required")
	}

	displayName := c.FormValue("display_name")
	name := c.FormValue("name")
	if err := validateTenantName(name); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	ctx := context.Background()
	now := time.Now().Unix()
	insertRes, err := adminDB.ExecContext(
		ctx,
		"INSERT INTO tenant (name, display_name, created_at, updated_at) VALUES (?, ?, ?, ?)",
		name, displayName, now, now,
	)
	if err != nil {
		if merr, ok := err.(*mysql.MySQLError); ok && merr.Number == 1062 { // duplicate entry
			return echo.NewHTTPError(http.StatusBadRequest, "duplicate tenant")
		}
		return fmt.Errorf(
			"error Insert tenant: name=%s, displayName=%s, createdAt=%d, updatedAt=%d, %w",
			name, displayName, now, now, err,
		)
	}

	id, err := insertRes.LastInsertId()
	if err != nil {
		return fmt.Errorf("error get LastInsertId: %w", err)
	}
	// NOTE: 先にadminDBに書き込まれることでこのAPIの処理中に
	//       /api/admin/tenants/billingにアクセスされるとエラーになりそう
	//       ロックなどで対処したほうが良さそう
	// if err := createTenantDB(id); err != nil {
	// 	return fmt.Errorf("error createTenantDB: id=%d name=%s %w", id, name, err)
	// }

	res := TenantsAddHandlerResult{
		Tenant: TenantWithBilling{
			ID:          strconv.FormatInt(id, 10),
			Name:        name,
			DisplayName: displayName,
			BillingYen:  0,
		},
	}
	return c.JSON(http.StatusOK, SuccessResult{Status: true, Data: res})
}

// テナント名が規則に沿っているかチェックする
func validateTenantName(name string) error {
	if tenantNameRegexp.MatchString(name) {
		return nil
	}
	return fmt.Errorf("invalid tenant name: %s", name)
}

type BillingReport struct {
	CompetitionID     string `json:"competition_id"`
	CompetitionTitle  string `json:"competition_title"`
	PlayerCount       int64  `json:"player_count"`        // スコアを登録した参加者数
	VisitorCount      int64  `json:"visitor_count"`       // ランキングを閲覧だけした(スコアを登録していない)参加者数
	BillingPlayerYen  int64  `json:"billing_player_yen"`  // 請求金額 スコアを登録した参加者分
	BillingVisitorYen int64  `json:"billing_visitor_yen"` // 請求金額 ランキングを閲覧だけした(スコアを登録していない)参加者分
	BillingYen        int64  `json:"billing_yen"`         // 合計請求金額
}

type VisitHistoryRow struct {
	PlayerID      string `db:"player_id"`
	TenantID      int64  `db:"tenant_id"`
	CompetitionID string `db:"competition_id"`
	CreatedAt     int64  `db:"created_at"`
	UpdatedAt     int64  `db:"updated_at"`
}

type VisitHistorySummaryRow struct {
	PlayerID     string `db:"player_id"`
	MinCreatedAt int64  `db:"min_created_at"`
}

// 大会ごとの課金レポートを計算する
func billingReportByCompetition(ctx context.Context, tenantID int64, competitonID string) (*BillingReport, error) {
	comp, err := retrieveCompetition(ctx, tenantDBs[tenantID%2^1], competitonID)
	if err != nil {
		return nil, fmt.Errorf("error retrieveCompetition: %w", err)
	}

	// ランキングにアクセスした参加者のIDを取得する
	billingMap := map[string]string{}
	for _, playerID := range visitMap.get(competitonID) {
		billingMap[playerID] = "visitor"
	}

	// player_scoreを読んでいるときに更新が走ると不整合が起こるのでロックを取得する
	// fl, err := flockByTenantID(tenantID)
	// if err != nil {
	// 	return nil, fmt.Errorf("error flockByTenantID: %w", err)
	// }
	// defer fl.Close()

	// スコアを登録した参加者のIDを取得する
	scoredPlayerIDs := []string{}
	if err := tenantDBs[tenantID%2^1].SelectContext(
		ctx,
		&scoredPlayerIDs,
		"SELECT DISTINCT(player_id) FROM player_score WHERE competition_id = ?",
		comp.ID,
	); err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("error Select count player_score: tenantID=%d, competitionID=%s, %w", tenantID, competitonID, err)
	}
	for _, pid := range scoredPlayerIDs {
		// スコアが登録されている参加者
		billingMap[pid] = "player"
	}

	// 大会が終了している場合のみ請求金額が確定するので計算する
	var playerCount, visitorCount int64
	if comp.FinishedAt.Valid {
		for _, category := range billingMap {
			switch category {
			case "player":
				playerCount++
			case "visitor":
				visitorCount++
			}
		}
	}
	return &BillingReport{
		CompetitionID:     comp.ID,
		CompetitionTitle:  comp.Title,
		PlayerCount:       playerCount,
		VisitorCount:      visitorCount,
		BillingPlayerYen:  100 * playerCount, // スコアを登録した参加者は100円
		BillingVisitorYen: 10 * visitorCount, // ランキングを閲覧だけした(スコアを登録していない)参加者は10円
		BillingYen:        100*playerCount + 10*visitorCount,
	}, nil
}

type TenantWithBilling struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	BillingYen  int64  `json:"billing"`
}

type TenantsBillingHandlerResult struct {
	Tenants []TenantWithBilling `json:"tenants"`
}

// SaaS管理者用API
// テナントごとの課金レポートを最大10件、テナントのid降順で取得する
// GET /api/admin/tenants/billing
// URL引数beforeを指定した場合、指定した値よりもidが小さいテナントの課金レポートを取得する
func tenantsBillingHandler(c echo.Context) error {
	if host := c.Request().Host; host != getEnv("ISUCON_ADMIN_HOSTNAME", "admin.t.isucon.local") {
		return echo.NewHTTPError(
			http.StatusNotFound,
			fmt.Sprintf("invalid hostname %s", host),
		)
	}

	ctx := context.Background()
	if v, err := parseViewer(c); err != nil {
		return err
	} else if v.role != RoleAdmin {
		return echo.NewHTTPError(http.StatusForbidden, "admin role required")
	}

	before := c.QueryParam("before")
	var beforeID int64
	if before != "" {
		var err error
		beforeID, err = strconv.ParseInt(before, 10, 64)
		if err != nil {
			return echo.NewHTTPError(
				http.StatusBadRequest,
				fmt.Sprintf("failed to parse query parameter 'before': %s", err.Error()),
			)
		}
	}
	// テナントごとに
	//   大会ごとに
	//     scoreが登録されているplayer * 100
	//     scoreが登録されていないplayerでアクセスした人 * 10
	//   を合計したものを
	// テナントの課金とする
	ts := []TenantRow{}
	if err := adminDB.SelectContext(ctx, &ts, "SELECT * FROM tenant ORDER BY id DESC"); err != nil {
		return fmt.Errorf("error Select tenant: %w", err)
	}
	tenantBillings := make([]TenantWithBilling, 0, len(ts))
	for _, t := range ts {
		if beforeID != 0 && beforeID <= t.ID {
			continue
		}
		err := func(t TenantRow) error {
			tb := TenantWithBilling{
				ID:          strconv.FormatInt(t.ID, 10),
				Name:        t.Name,
				DisplayName: t.DisplayName,
			}
			cs := []CompetitionRow{}
			if err := tenantDBs[t.ID%2^1].SelectContext(
				ctx,
				&cs,
				"SELECT * FROM competition WHERE tenant_id=?",
				t.ID,
			); err != nil {
				return fmt.Errorf("failed to Select competition: %w", err)
			}
			for _, comp := range cs {
				report, err := billingReportByCompetition(ctx, t.ID, comp.ID)
				if err != nil {
					return fmt.Errorf("failed to billingReportByCompetition: %w", err)
				}
				tb.BillingYen += report.BillingYen
			}
			tenantBillings = append(tenantBillings, tb)
			return nil
		}(t)
		if err != nil {
			return err
		}
		if len(tenantBillings) >= 10 {
			break
		}
	}
	return c.JSON(http.StatusOK, SuccessResult{
		Status: true,
		Data: TenantsBillingHandlerResult{
			Tenants: tenantBillings,
		},
	})
}

type PlayerDetail struct {
	ID             string `json:"id"`
	DisplayName    string `json:"display_name"`
	IsDisqualified bool   `json:"is_disqualified"`
}

type PlayersListHandlerResult struct {
	Players []PlayerDetail `json:"players"`
}

// テナント管理者向けAPI
// GET /api/organizer/players
// 参加者一覧を返す
func playersListHandler(c echo.Context) error {
	ctx := context.Background()
	v, err := parseViewer(c)
	if err != nil {
		return err
	} else if v.role != RoleOrganizer {
		return echo.NewHTTPError(http.StatusForbidden, "role organizer required")
	}

	var pls []PlayerRow
	if err := tenantDBs[v.tenantID%2^1].SelectContext(
		ctx,
		&pls,
		"SELECT * FROM player WHERE tenant_id=? ORDER BY created_at DESC",
		v.tenantID,
	); err != nil {
		return fmt.Errorf("error Select player: %w", err)
	}
	var pds []PlayerDetail
	for _, p := range pls {
		pds = append(pds, PlayerDetail{
			ID:             p.ID,
			DisplayName:    p.DisplayName,
			IsDisqualified: p.IsDisqualified,
		})
	}

	res := PlayersListHandlerResult{
		Players: pds,
	}
	return c.JSON(http.StatusOK, SuccessResult{Status: true, Data: res})
}

type PlayersAddHandlerResult struct {
	Players []PlayerDetail `json:"players"`
}

// テナント管理者向けAPI
// GET /api/organizer/players/add
// テナントに参加者を追加する
func playersAddHandler(c echo.Context) error {
	ctx := context.Background()
	v, err := parseViewer(c)
	if err != nil {
		return fmt.Errorf("error parseViewer: %w", err)
	} else if v.role != RoleOrganizer {
		return echo.NewHTTPError(http.StatusForbidden, "role organizer required")
	}

	params, err := c.FormParams()
	if err != nil {
		return fmt.Errorf("error c.FormParams: %w", err)
	}
	displayNames := params["display_name[]"]

	pds := make([]PlayerDetail, 0, len(displayNames))
	for _, displayName := range displayNames {
		id, err := dispenseID(ctx)
		if err != nil {
			return fmt.Errorf("error dispenseID: %w", err)
		}

		now := time.Now().Unix()
		if _, err := tenantDBs[v.tenantID%2^1].ExecContext(
			ctx,
			"INSERT INTO player (id, tenant_id, display_name, is_disqualified, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
			id, v.tenantID, displayName, false, now, now,
		); err != nil {
			return fmt.Errorf(
				"error Insert player at tenantDB: id=%s, displayName=%s, isDisqualified=%t, createdAt=%d, updatedAt=%d, %w",
				id, displayName, false, now, now, err,
			)
		}
		// p, err := retrievePlayer(ctx, tenantDBs[v.tenantID%2^1], id)
		// if err != nil {
		// 	return fmt.Errorf("error retrievePlayer: %w", err)
		// }
		pds = append(pds, PlayerDetail{
			ID:             id,
			DisplayName:    displayName,
			IsDisqualified: false,
		})
		playerID2Name.set(id, displayName)
	}

	res := PlayersAddHandlerResult{
		Players: pds,
	}
	return c.JSON(http.StatusOK, SuccessResult{Status: true, Data: res})
}

type PlayerDisqualifiedHandlerResult struct {
	Player PlayerDetail `json:"player"`
}

// テナント管理者向けAPI
// POST /api/organizer/player/:player_id/disqualified
// 参加者を失格にする
func playerDisqualifiedHandler(c echo.Context) error {
	ctx := context.Background()
	v, err := parseViewer(c)
	if err != nil {
		return fmt.Errorf("error parseViewer: %w", err)
	} else if v.role != RoleOrganizer {
		return echo.NewHTTPError(http.StatusForbidden, "role organizer required")
	}

	playerID := c.Param("player_id")

	now := time.Now().Unix()
	if _, err := tenantDBs[v.tenantID%2^1].ExecContext(
		ctx,
		"UPDATE player SET is_disqualified = ?, updated_at = ? WHERE id = ?",
		true, now, playerID,
	); err != nil {
		return fmt.Errorf(
			"error Update player: isDisqualified=%t, updatedAt=%d, id=%s, %w",
			true, now, playerID, err,
		)
	}
	p, err := retrievePlayer(ctx, tenantDBs[v.tenantID%2^1], playerID)
	if err != nil {
		// 存在しないプレイヤー
		if errors.Is(err, sql.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound, "player not found")
		}
		return fmt.Errorf("error retrievePlayer: %w", err)
	}

	res := PlayerDisqualifiedHandlerResult{
		Player: PlayerDetail{
			ID:             p.ID,
			DisplayName:    p.DisplayName,
			IsDisqualified: p.IsDisqualified,
		},
	}
	return c.JSON(http.StatusOK, SuccessResult{Status: true, Data: res})
}

type CompetitionDetail struct {
	ID         string `json:"id"`
	Title      string `json:"title"`
	IsFinished bool   `json:"is_finished"`
}

type CompetitionsAddHandlerResult struct {
	Competition CompetitionDetail `json:"competition"`
}

// テナント管理者向けAPI
// POST /api/organizer/competitions/add
// 大会を追加する
func competitionsAddHandler(c echo.Context) error {
	ctx := context.Background()
	v, err := parseViewer(c)
	if err != nil {
		return fmt.Errorf("error parseViewer: %w", err)
	} else if v.role != RoleOrganizer {
		return echo.NewHTTPError(http.StatusForbidden, "role organizer required")
	}

	title := c.FormValue("title")

	now := time.Now().Unix()
	id, err := dispenseID(ctx)
	if err != nil {
		return fmt.Errorf("error dispenseID: %w", err)
	}

	if _, err := tenantDBs[v.tenantID%2^1].ExecContext(
		ctx,
		"INSERT INTO competition (id, tenant_id, title, finished_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
		id, v.tenantID, title, sql.NullInt64{}, now, now,
	); err != nil {
		return fmt.Errorf(
			"error Insert competition: id=%s, tenant_id=%d, title=%s, finishedAt=null, createdAt=%d, updatedAt=%d, %w",
			id, v.tenantID, title, now, now, err,
		)
	}

	competitionID2Title.set(id, title)
	res := CompetitionsAddHandlerResult{
		Competition: CompetitionDetail{
			ID:         id,
			Title:      title,
			IsFinished: false,
		},
	}
	return c.JSON(http.StatusOK, SuccessResult{Status: true, Data: res})
}

// テナント管理者向けAPI
// POST /api/organizer/competition/:competition_id/finish
// 大会を終了する
func competitionFinishHandler(c echo.Context) error {
	ctx := context.Background()
	v, err := parseViewer(c)
	if err != nil {
		return fmt.Errorf("error parseViewer: %w", err)
	} else if v.role != RoleOrganizer {
		return echo.NewHTTPError(http.StatusForbidden, "role organizer required")
	}

	id := c.Param("competition_id")
	if id == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "competition_id required")
	}
	_, err = retrieveCompetition(ctx, tenantDBs[v.tenantID%2^1], id)
	if err != nil {
		// 存在しない大会
		if errors.Is(err, sql.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound, "competition not found")
		}
		return fmt.Errorf("error retrieveCompetition: %w", err)
	}

	now := time.Now().Unix()
	if _, err := tenantDBs[v.tenantID%2^1].ExecContext(
		ctx,
		"UPDATE competition SET finished_at = ?, updated_at = ? WHERE id = ?",
		now, now, id,
	); err != nil {
		return fmt.Errorf(
			"error Update competition: finishedAt=%d, updatedAt=%d, id=%s, %w",
			now, now, id, err,
		)
	}
	return c.JSON(http.StatusOK, SuccessResult{Status: true})
}

type ScoreHandlerResult struct {
	Rows int64 `json:"rows"`
}

// テナント管理者向けAPI
// POST /api/organizer/competition/:competition_id/score
// 大会のスコアをCSVでアップロードする
func competitionScoreHandler(c echo.Context) error {
	ctx := context.Background()
	v, err := parseViewer(c)
	if err != nil {
		return fmt.Errorf("error parseViewer: %w", err)
	}
	if v.role != RoleOrganizer {
		return echo.NewHTTPError(http.StatusForbidden, "role organizer required")
	}

	competitionID := c.Param("competition_id")
	if competitionID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "competition_id required")
	}
	comp, err := retrieveCompetition(ctx, tenantDBs[v.tenantID%2^1], competitionID)
	if err != nil {
		// 存在しない大会
		if errors.Is(err, sql.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound, "competition not found")
		}
		return fmt.Errorf("error retrieveCompetition: %w", err)
	}
	if comp.FinishedAt.Valid {
		res := FailureResult{
			Status:  false,
			Message: "competition is finished",
		}
		return c.JSON(http.StatusBadRequest, res)
	}

	fh, err := c.FormFile("scores")
	if err != nil {
		return fmt.Errorf("error c.FormFile(scores): %w", err)
	}
	f, err := fh.Open()
	if err != nil {
		return fmt.Errorf("error fh.Open FormFile(scores): %w", err)
	}
	defer f.Close()

	r := csv.NewReader(f)
	headers, err := r.Read()
	if err != nil {
		return fmt.Errorf("error r.Read at header: %w", err)
	}
	if !reflect.DeepEqual(headers, []string{"player_id", "score"}) {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid CSV headers")
	}

	// / DELETEしたタイミングで参照が来ると空っぽのランキングになるのでロックする
	// fl, err := flockByTenantID(v.tenantID)
	// if err != nil {
	// 	return fmt.Errorf("error flockByTenantID: %w", err)
	// }
	// defer fl.Close()

	var rowNum int64
	type playerIDAndScore struct {
		playerID string
		score    int64
	}
	var playerIDAndScores []playerIDAndScore
	for {
		rowNum++
		row, err := r.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("error r.Read at rows: %w", err)
		}
		if len(row) != 2 {
			return fmt.Errorf("row must have two columns: %#v", row)
		}
		playerID, scoreStr := row[0], row[1]
		var score int64
		if score, err = strconv.ParseInt(scoreStr, 10, 64); err != nil {
			return echo.NewHTTPError(
				http.StatusBadRequest,
				fmt.Sprintf("error strconv.ParseUint: scoreStr=%s, %s", scoreStr, err),
			)
		}
		playerIDAndScores = append(playerIDAndScores, playerIDAndScore{
			playerID: playerID,
			score:    score,
		})
	}

	playerIDSet := map[string]struct{}{}
	var playerIDs []string
	for _, val := range playerIDAndScores {
		if _, ok := playerIDSet[val.playerID]; !ok {
			playerIDSet[val.playerID] = struct{}{}
			playerIDs = append(playerIDs, val.playerID)
		}
	}

	if len(playerIDs) > 0 {
		sqlStmt := "SELECT id FROM player WHERE id IN (?)"
		sqlStmt, params, _ := sqlx.In(sqlStmt, playerIDs)
		var retrivePlayerIDs1 []string
		var retrivePlayerIDs2 []string
		if err := tenantDBs[0].SelectContext(ctx, &retrivePlayerIDs1, sqlStmt, params...); err != nil {
			return fmt.Errorf("error retrievePlayer from tenantDB0: %w", err)
		}
		if err := tenantDBs[1].SelectContext(ctx, &retrivePlayerIDs2, sqlStmt, params...); err != nil {
			return fmt.Errorf("error retrievePlayer from tenantDB1: %w", err)
		}

		retrivePlayerIDSet := map[string]struct{}{}
		for _, playerID := range retrivePlayerIDs1 {
			retrivePlayerIDSet[playerID] = struct{}{}
		}
		for _, playerID := range retrivePlayerIDs2 {
			retrivePlayerIDSet[playerID] = struct{}{}
		}
		for _, playerID := range playerIDs {
			if _, ok := retrivePlayerIDSet[playerID]; !ok {
				return echo.NewHTTPError(
					http.StatusBadRequest,
					fmt.Sprintf("player not found: %s", playerID),
				)
			}
		}
	}

	playerScoreRows := []PlayerScoreRow{}
	type insertRow struct {
		ID            string `db:"id"`
		TenantID      int64  `db:"tenant_id"`
		PlayerID      string `db:"player_id"`
		CompetitionID string `db:"competition_id"`
		Score         int64  `db:"score"`
		RowNum        int64  `db:"row_num"`
		CreatedAt     int64  `db:"created_at"`
		UpdatedAt     int64  `db:"updated_at"`
	}
	insertRowByPlayer := map[string]insertRow{}
	for _, val := range playerIDAndScores {
		playerID := val.playerID
		score := val.score
		id, err := dispenseID(ctx)
		if err != nil {
			return fmt.Errorf("error dispenseID: %w", err)
		}
		now := time.Now().Unix()
		playerScoreRows = append(playerScoreRows, PlayerScoreRow{
			ID:            id,
			TenantID:      v.tenantID,
			PlayerID:      playerID,
			CompetitionID: competitionID,
			Score:         score,
			RowNum:        rowNum,
			CreatedAt:     now,
			UpdatedAt:     now,
		})

		insertRowByPlayer[playerID] = insertRow{
			ID:            id,
			TenantID:      v.tenantID,
			PlayerID:      playerID,
			CompetitionID: competitionID,
			Score:         score,
			RowNum:        rowNum,
			CreatedAt:     now,
			UpdatedAt:     now,
		}
	}
	insertRows := make([]insertRow, 0, len(insertRowByPlayer))
	for _, val := range insertRowByPlayer {
		insertRows = append(insertRows, val)
	}
	sort.Slice(insertRows, func(i, j int) bool { return insertRows[i].ID < insertRows[j].ID })

	bulkInsertMutex.Lock()
	defer bulkInsertMutex.Unlock()
	tx, _ := tenantDBs[v.tenantID%2^1].Beginx()
	if _, err := tx.ExecContext(
		ctx,
		"DELETE FROM player_score WHERE competition_id = ?",
		competitionID,
	); err != nil {
		return fmt.Errorf("error Delete player_score: tenantID=%d, competitionID=%s, %w", v.tenantID, competitionID, err)
	}
	if _, err := tx.NamedExecContext(
		ctx,
		"INSERT INTO player_score (id, tenant_id, player_id, competition_id, score, row_num, created_at, updated_at) VALUES (:id, :tenant_id, :player_id, :competition_id, :score, :row_num, :created_at, :updated_at)",
		insertRows,
	); err != nil {
		return fmt.Errorf("error Bulk Insert player_score: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("error transaction: %w", err)
	}

	return c.JSON(http.StatusOK, SuccessResult{
		Status: true,
		Data:   ScoreHandlerResult{Rows: int64(len(playerScoreRows))},
	})
}

type BillingHandlerResult struct {
	Reports []BillingReport `json:"reports"`
}

// テナント管理者向けAPI
// GET /api/organizer/billing
// テナント内の課金レポートを取得する
func billingHandler(c echo.Context) error {
	ctx := context.Background()
	v, err := parseViewer(c)
	if err != nil {
		return fmt.Errorf("error parseViewer: %w", err)
	}
	if v.role != RoleOrganizer {
		return echo.NewHTTPError(http.StatusForbidden, "role organizer required")
	}

	cs := []CompetitionRow{}
	if err := tenantDBs[v.tenantID%2^1].SelectContext(
		ctx,
		&cs,
		"SELECT * FROM competition WHERE tenant_id=? ORDER BY created_at DESC",
		v.tenantID,
	); err != nil {
		return fmt.Errorf("error Select competition: %w", err)
	}
	tbrs := make([]BillingReport, 0, len(cs))
	for _, comp := range cs {
		report, err := billingReportByCompetition(ctx, v.tenantID, comp.ID)
		if err != nil {
			return fmt.Errorf("error billingReportByCompetition: %w", err)
		}
		tbrs = append(tbrs, *report)
	}

	res := SuccessResult{
		Status: true,
		Data: BillingHandlerResult{
			Reports: tbrs,
		},
	}
	return c.JSON(http.StatusOK, res)
}

type PlayerScoreDetail struct {
	CompetitionTitle string `json:"competition_title"`
	Score            int64  `json:"score"`
}

type PlayerHandlerResult struct {
	Player PlayerDetail        `json:"player"`
	Scores []PlayerScoreDetail `json:"scores"`
}

// 参加者向けAPI
// GET /api/player/player/:player_id
// 参加者の詳細情報を取得する
func playerHandler(c echo.Context) error {
	ctx := context.Background()

	v, err := parseViewer(c)
	if err != nil {
		return err
	}
	if v.role != RolePlayer {
		return echo.NewHTTPError(http.StatusForbidden, "role player required")
	}

	if err := authorizePlayer(ctx, tenantDBs[v.tenantID%2^1], v.playerID); err != nil {
		return err
	}

	playerID := c.Param("player_id")
	if playerID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "player_id is required")
	}
	p, err := retrievePlayer(ctx, tenantDBs[v.tenantID%2^1], playerID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound, "player not found")
		}
		return fmt.Errorf("error retrievePlayer: %w", err)
	}
	cs := []CompetitionRow{}
	if err := tenantDBs[v.tenantID%2^1].SelectContext(
		ctx,
		&cs,
		"SELECT * FROM competition WHERE tenant_id = ? ORDER BY created_at ASC",
		v.tenantID,
	); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("error Select competition: %w", err)
	}

	// player_scoreを読んでいるときに更新が走ると不整合が起こるのでロックを取得する
	// fl, err := flockByTenantID(v.tenantID)
	// if err != nil {
	// 	return fmt.Errorf("error flockByTenantID: %w", err)
	// }
	// defer fl.Close()

	// SQLインジェクションを許容
	pss := make([]PlayerScoreRow, 0, len(cs))
	whereInArgs := make([]string, 0, len(cs))
	for _, c := range cs {
		whereInArgs = append(whereInArgs, fmt.Sprintf("(%d, \"%s\", \"%s\")", v.tenantID, c.ID, p.ID))
	}
	inStmt := strings.Join(whereInArgs, ", ")
	sqlStmt := fmt.Sprintf("SELECT * FROM player_score WHERE (tenant_id, competition_id, player_id) IN (%s)", inStmt)
	if err := tenantDBs[v.tenantID%2^1].SelectContext(ctx, &pss, sqlStmt); err != nil {
		return fmt.Errorf("error Select player_score, %w", err)
	}

	psds := make([]PlayerScoreDetail, 0, len(pss))

	if len(pss) > 0 { // 長さ0だとsqlx.Inでエラーになる
		// competitionIDs := make([]string, 0, len(pss))
		// for _, ps := range pss {
		// 	competitionIDs = append(competitionIDs, ps.CompetitionID)
		// }

		// type competitionIDAndTitle struct {
		// 	ID    string `db:"id"`
		// 	Title string `db:"title"`
		// }
		// competitionIDAndTitles := make([]competitionIDAndTitle, 0, len(competitionIDs))

		// sqlStmt = "SELECT id, title FROM competition WHERE id IN (?)"
		// sqlStmt, params, _ := sqlx.In(sqlStmt, competitionIDs)
		// if err := tenantDBs[v.tenantID%2^1].SelectContext(ctx, &competitionIDAndTitles, sqlStmt, params...); err != nil {
		// 	return fmt.Errorf("error Select competition, %w", err)
		// }

		// competitionID2Title := map[string]string{}
		// for _, c := range competitionIDAndTitles {
		// 	competitionID2Title[c.ID] = c.Title
		// }

		for _, ps := range pss {
			psds = append(psds, PlayerScoreDetail{
				CompetitionTitle: competitionID2Title.get(ps.CompetitionID),
				Score:            ps.Score,
			})
		}
	}

	res := SuccessResult{
		Status: true,
		Data: PlayerHandlerResult{
			Player: PlayerDetail{
				ID:             p.ID,
				DisplayName:    p.DisplayName,
				IsDisqualified: p.IsDisqualified,
			},
			Scores: psds,
		},
	}
	return c.JSON(http.StatusOK, res)
}

type CompetitionRank struct {
	Rank              int64  `json:"rank"`
	Score             int64  `json:"score"`
	PlayerID          string `json:"player_id"`
	PlayerDisplayName string `json:"player_display_name"`
	RowNum            int64  `json:"-"` // APIレスポンスのJSONには含まれない
}

type CompetitionRankingHandlerResult struct {
	Competition CompetitionDetail `json:"competition"`
	Ranks       []CompetitionRank `json:"ranks"`
}

// 参加者向けAPI
// GET /api/player/competition/:competition_id/ranking
// 大会ごとのランキングを取得する
func competitionRankingHandler(c echo.Context) error {
	ctx := context.Background()
	v, err := parseViewer(c)
	if err != nil {
		return err
	}
	if v.role != RolePlayer {
		return echo.NewHTTPError(http.StatusForbidden, "role player required")
	}

	if err := authorizePlayer(ctx, tenantDBs[v.tenantID%2^1], v.playerID); err != nil {
		return err
	}

	competitionID := c.Param("competition_id")
	if competitionID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "competition_id is required")
	}

	// 大会の存在確認
	competition, err := retrieveCompetition(ctx, tenantDBs[v.tenantID%2^1], competitionID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound, "competition not found")
		}
		return fmt.Errorf("error retrieveCompetition: %w", err)
	}

	now := time.Now().Unix()
	// var tenant TenantRow
	// if err := adminDB.GetContext(ctx, &tenant, "SELECT * FROM tenant WHERE id = ?", v.tenantID); err != nil {
	// 	return fmt.Errorf("error Select tenant: id=%d, %w", v.tenantID, err)
	// }

	if !competition.FinishedAt.Valid || (now <= competition.FinishedAt.Int64) { // 大会開催内のみ記録する
		visitMap.set(competitionID, v.playerID)
	}

	var rankAfter int64
	rankAfterStr := c.QueryParam("rank_after")
	if rankAfterStr != "" {
		if rankAfter, err = strconv.ParseInt(rankAfterStr, 10, 64); err != nil {
			return fmt.Errorf("error strconv.ParseUint: rankAfterStr=%s, %w", rankAfterStr, err)
		}
	}

	// player_scoreを読んでいるときに更新が走ると不整合が起こるのでロックを取得する
	// fl, err := flockByTenantID(v.tenantID)
	// if err != nil {
	// 	return fmt.Errorf("error flockByTenantID: %w", err)
	// }
	// defer fl.Close()

	pss := []PlayerScoreRow{}
	if err := tenantDBs[v.tenantID%2^1].SelectContext(
		ctx,
		&pss,
		"SELECT * FROM player_score WHERE competition_id = ? ORDER BY score DESC, row_num LIMIT 100 OFFSET ?",
		competitionID,
		rankAfter,
	); err != nil {
		return fmt.Errorf("error Select player_score2: competitionID=%s, rankafter=%d, %w", competitionID, rankAfter, err)
	}

	ranks := make([]CompetitionRank, 0, len(pss))

	if len(pss) > 0 { // 長さ0だとsqlx.Inでエラーになる
		// playerIDs := make([]string, 0, len(pss))
		// for _, ps := range pss {
		// 	playerIDs = append(playerIDs, ps.PlayerID)
		// }

		// type playerIDAndName struct {
		// 	ID          string `db:"id"`
		// 	DisplayName string `db:"display_name"`
		// }
		// playerIDAndNames := make([]playerIDAndName, 0, len(playerIDs))
		// sqlStmt := "SELECT id, display_name FROM player WHERE id IN (?)"
		// sqlStmt, params, _ := sqlx.In(sqlStmt, playerIDs)
		// if err := tenantDBs[v.tenantID%2^1].SelectContext(ctx, &playerIDAndNames, sqlStmt, params...); err != nil {
		// 	return fmt.Errorf("error select player id and name: %w", err)
		// }

		// playerID2Name := map[string]string{}
		// for _, p := range playerIDAndNames {
		// 	playerID2Name[p.ID] = p.DisplayName
		// }

		for _, ps := range pss {
			ranks = append(ranks, CompetitionRank{
				Score:             ps.Score,
				PlayerID:          ps.PlayerID,
				PlayerDisplayName: playerID2Name.get(ps.PlayerID),
				RowNum:            ps.RowNum,
			})
		}
	}

	pagedRanks := make([]CompetitionRank, 0, 100)
	for i, rank := range ranks {
		pagedRanks = append(pagedRanks, CompetitionRank{
			Rank:              rankAfter + int64(i + 1),
			Score:             rank.Score,
			PlayerID:          rank.PlayerID,
			PlayerDisplayName: rank.PlayerDisplayName,
		})
	}

	res := SuccessResult{
		Status: true,
		Data: CompetitionRankingHandlerResult{
			Competition: CompetitionDetail{
				ID:         competition.ID,
				Title:      competition.Title,
				IsFinished: competition.FinishedAt.Valid,
			},
			Ranks: pagedRanks,
		},
	}
	return c.JSON(http.StatusOK, res)
}

type CompetitionsHandlerResult struct {
	Competitions []CompetitionDetail `json:"competitions"`
}

// 参加者向けAPI
// GET /api/player/competitions
// 大会の一覧を取得する
func playerCompetitionsHandler(c echo.Context) error {
	ctx := context.Background()

	v, err := parseViewer(c)
	if err != nil {
		return err
	}
	if v.role != RolePlayer {
		return echo.NewHTTPError(http.StatusForbidden, "role player required")
	}

	if err := authorizePlayer(ctx, tenantDBs[v.tenantID%2^1], v.playerID); err != nil {
		return err
	}
	return competitionsHandler(c, v, tenantDBs[v.tenantID%2^1])
}

// テナント管理者向けAPI
// GET /api/organizer/competitions
// 大会の一覧を取得する
func organizerCompetitionsHandler(c echo.Context) error {
	v, err := parseViewer(c)
	if err != nil {
		return err
	}
	if v.role != RoleOrganizer {
		return echo.NewHTTPError(http.StatusForbidden, "role organizer required")
	}

	return competitionsHandler(c, v, tenantDBs[v.tenantID%2^1])
}

func competitionsHandler(c echo.Context, v *Viewer, tenantDB dbOrTx) error {
	ctx := context.Background()

	cs := []CompetitionRow{}
	if err := tenantDB.SelectContext(
		ctx,
		&cs,
		"SELECT * FROM competition WHERE tenant_id=? ORDER BY created_at DESC",
		v.tenantID,
	); err != nil {
		return fmt.Errorf("error Select competition: %w", err)
	}
	cds := make([]CompetitionDetail, 0, len(cs))
	for _, comp := range cs {
		cds = append(cds, CompetitionDetail{
			ID:         comp.ID,
			Title:      comp.Title,
			IsFinished: comp.FinishedAt.Valid,
		})
	}

	res := SuccessResult{
		Status: true,
		Data: CompetitionsHandlerResult{
			Competitions: cds,
		},
	}
	return c.JSON(http.StatusOK, res)
}

type TenantDetail struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
}

type MeHandlerResult struct {
	Tenant   *TenantDetail `json:"tenant"`
	Me       *PlayerDetail `json:"me"`
	Role     string        `json:"role"`
	LoggedIn bool          `json:"logged_in"`
}

// 共通API
// GET /api/me
// JWTで認証した結果、テナントやユーザ情報を返す
func meHandler(c echo.Context) error {
	tenant, err := retrieveTenantRowFromHeader(c)
	if err != nil {
		return fmt.Errorf("error retrieveTenantRowFromHeader: %w", err)
	}
	td := &TenantDetail{
		Name:        tenant.Name,
		DisplayName: tenant.DisplayName,
	}
	v, err := parseViewer(c)
	if err != nil {
		var he *echo.HTTPError
		if ok := errors.As(err, &he); ok && he.Code == http.StatusUnauthorized {
			return c.JSON(http.StatusOK, SuccessResult{
				Status: true,
				Data: MeHandlerResult{
					Tenant:   td,
					Me:       nil,
					Role:     RoleNone,
					LoggedIn: false,
				},
			})
		}
		return fmt.Errorf("error parseViewer: %w", err)
	}
	if v.role == RoleAdmin || v.role == RoleOrganizer {
		return c.JSON(http.StatusOK, SuccessResult{
			Status: true,
			Data: MeHandlerResult{
				Tenant:   td,
				Me:       nil,
				Role:     v.role,
				LoggedIn: true,
			},
		})
	}

	ctx := context.Background()
	p, err := retrievePlayer(ctx, tenantDBs[v.tenantID%2^1], v.playerID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return c.JSON(http.StatusOK, SuccessResult{
				Status: true,
				Data: MeHandlerResult{
					Tenant:   td,
					Me:       nil,
					Role:     RoleNone,
					LoggedIn: false,
				},
			})
		}
		return fmt.Errorf("error retrievePlayer: %w", err)
	}

	return c.JSON(http.StatusOK, SuccessResult{
		Status: true,
		Data: MeHandlerResult{
			Tenant: td,
			Me: &PlayerDetail{
				ID:             p.ID,
				DisplayName:    p.DisplayName,
				IsDisqualified: p.IsDisqualified,
			},
			Role:     v.role,
			LoggedIn: true,
		},
	})
}

type InitializeHandlerResult struct {
	Lang string `json:"lang"`
}

// ベンチマーカー向けAPI
// POST /initialize
// ベンチマーカーが起動したときに最初に呼ぶ
// データベースの初期化などが実行されるため、スキーマを変更した場合などは適宜改変すること
func initializeHandler(c echo.Context) error {
	out, err := exec.Command(initializeScript).CombinedOutput()
	if err != nil {
		return fmt.Errorf("error exec.Command: %s %e", string(out), err)
	}
	type sqlResult1 struct {
		PlayerID      string `db:"player_id"`
		TenantID      int64  `db:"tenant_id"`
		CompetitionID string `db:"competition_id"`
	}
	var sqlResults1 []sqlResult1
	if err := adminDB.SelectContext(
		context.Background(),
		&sqlResults1,
		"SELECT player_id, tenant_id, competition_id FROM visit_history",
	); err != nil {
		return fmt.Errorf("select visit history failed: %e", err)
	}

	for _, sqlResult := range sqlResults1 {
		visitMap.set(sqlResult.CompetitionID, sqlResult.PlayerID)
	}

	type sqlResult2 struct {
		CompetitionID    string `db:"id"`
		CompetitionTitle string `db:"title"`
	}
	var sqlResults2 []sqlResult2
	if err := tenantDBs[0].SelectContext(
		context.Background(),
		&sqlResults2,
		"SELECT id, title FROM competition",
	); err != nil {
		return fmt.Errorf("select competition from tenantDB0 failed: %e", err)
	}
	for _, sqlResult := range sqlResults2 {
		competitionID2Title.set(sqlResult.CompetitionID, sqlResult.CompetitionTitle)
	}
	sqlResults2 = nil
	if err := tenantDBs[1].SelectContext(
		context.Background(),
		&sqlResults2,
		"SELECT id, title FROM competition",
	); err != nil {
		return fmt.Errorf("select competition from tenantDB1 failed: %e", err)
	}
	for _, sqlResult := range sqlResults2 {
		competitionID2Title.set(sqlResult.CompetitionID, sqlResult.CompetitionTitle)
	}

	type sqlResult3 struct {
		PlayerID   string `db:"id"`
		PlayerName string `db:"display_name"`
	}
	var sqlResults3 []sqlResult3
	if err := tenantDBs[0].SelectContext(
		context.Background(),
		&sqlResults3,
		"SELECT id, display_name FROM player",
	); err != nil {
		return fmt.Errorf("select player from tenantDB0 failed: %e", err)
	}
	for _, sqlResult := range sqlResults3 {
		playerID2Name.set(sqlResult.PlayerID, sqlResult.PlayerName)
	}
	sqlResults3 = nil
	if err := tenantDBs[1].SelectContext(
		context.Background(),
		&sqlResults3,
		"SELECT id, display_name FROM player",
	); err != nil {
		return fmt.Errorf("select player from tenantDB1 failed: %e", err)
	}
	for _, sqlResult := range sqlResults3 {
		playerID2Name.set(sqlResult.PlayerID, sqlResult.PlayerName)
	}

	res := InitializeHandlerResult{
		Lang: "go",
	}
	return c.JSON(http.StatusOK, SuccessResult{Status: true, Data: res})
}
