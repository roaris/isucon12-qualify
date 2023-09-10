CREATE DATABASE IF NOT EXISTS `isuports_tenant`;
CREATE USER isucon IDENTIFIED BY 'isucon';
GRANT ALL PRIVILEGES ON isuports_tenant.* TO 'isucon'@'%';

SET PERSIST local_infile=1;
