package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func main() {
	fb, _ := os.Open("before.sql")
	fa1, _ := os.Create("after1.sql")
	fa2, _ := os.Create("after2.sql")
	defer fb.Close()
	defer fa1.Close()
	defer fa2.Close()

	scanner := bufio.NewScanner(fb)

	type mapKey struct {
		tenantID      string
		playerID      string
		competitionID string
	}
	type mapValue struct {
		id        string
		score     int64
		rowNum    int64
		createdAt int64
		updatedAt int64
	}
	m := map[mapKey]mapValue{}

	for scanner.Scan() {
		s := scanner.Text()

		if strings.Index(s, "INSERT INTO player_score") != -1 {
			s = strings.Split(s, " ")[3]
			l := strings.Split(s, ",")
			id := l[0][len("VALUES('") : len(l[0])-1]
			tenantID := l[1]
			playerID := l[2][1 : len(l[2])-1]
			competitionID := l[3][1 : len(l[3])-1]
			score, _ := strconv.ParseInt(l[4], 10, 64)
			rowNum, _ := strconv.ParseInt(l[5], 10, 64)
			createdAt, _ := strconv.ParseInt(l[6], 10, 64)
			updatedAt, _ := strconv.ParseInt(l[7][:len(l[7])-2], 10, 64)

			k := mapKey{
				tenantID:      tenantID,
				playerID:      playerID,
				competitionID: competitionID,
			}
			v := mapValue{
				id:        id,
				score:     score,
				rowNum:    rowNum,
				createdAt: createdAt,
				updatedAt: updatedAt,
			}

			m[k] = v
		} else if strings.Index(s, "INSERT INTO player") != -1 || strings.Index(s, "INSERT INTO competition") != -1 {
			fa1.Write([]byte(s + "\n"))
		}
	}

	for k, v := range m {
		s := fmt.Sprintf("INSERT INTO player_score VALUES('%s',%s,'%s','%s',%d,%d,%d,%d);", v.id, k.tenantID, k.playerID, k.competitionID, v.score, v.rowNum, v.createdAt, v.updatedAt)
		fa2.Write([]byte(s + "\n"))
	}
}
