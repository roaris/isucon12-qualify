CREATE INDEX tenant_id_index on competition(tenant_id);
CREATE INDEX tenant_id_index on player(tenant_id);
CREATE INDEX competition_id_index on player_score(competition_id);
CREATE INDEX tenant_id_and_competition_id_and_player_id_index on player_score(tenant_id, competition_id, player_id);