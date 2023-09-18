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
	fa, _ := os.Create("after.sql")
	defer fb.Close()
	defer fa.Close()

	scanner := bufio.NewScanner(fb)

	type mapKey struct {
		tenantID      string
		playerID      string
		competitionID string
	}
	type mapValue struct {
		id     string
		score  int64
		rowNum int64
	}
	m := map[mapKey]mapValue{}

	for scanner.Scan() {
		s := scanner.Text()

		if strings.Index(s, "INSERT INTO player_score") == -1 {
			fa.Write([]byte(s + "\n"))
		} else {
			s = strings.Split(s, " ")[3]
			l := strings.Split(s, ",")
			id := l[0][len("VALUES('") : len(l[0])-1]
			tenantID := l[1]
			playerID := l[2][1 : len(l[2])-1]
			competitionID := l[3][1 : len(l[3])-1]
			score, _ := strconv.ParseInt(l[4], 10, 64)
			rowNum, _ := strconv.ParseInt(l[5], 10, 64)

			k := mapKey{
				tenantID:      tenantID,
				playerID:      playerID,
				competitionID: competitionID,
			}
			v := mapValue{
				id:     id,
				score:  score,
				rowNum: rowNum,
			}

			m[k] = v
		}
	}

	for k, v := range m {
		s := fmt.Sprintf("INSERT INTO player_score VALUES('%s',%s,'%s','%s',%d,%d);", v.id, k.tenantID, k.playerID, k.competitionID, v.score, v.rowNum)
		fa.Write([]byte(s + "\n"))
	}
}
