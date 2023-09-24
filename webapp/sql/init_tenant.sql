-- 2023/8/1 0:00:00以降のデータを削除
DELETE FROM competition WHERE created_at >= 1690815600;
DELETE FROM player WHERE created_at >= 1690815600;
DELETE FROM player_score WHERE created_at >= 1690815600;
