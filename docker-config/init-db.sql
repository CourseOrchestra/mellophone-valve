CREATE TABLE users
(
    sid     VARCHAR(256) NOT NULL PRIMARY KEY,
    login   VARCHAR,
    pwd     VARCHAR,
    blocked BOOLEAN      NOT NULL DEFAULT FALSE,
    UNIQUE (login)
);

CREATE TABLE user_attr
(
    sid        VARCHAR(256) NOT NULL,
    fieldid    VARCHAR      NOT NULL,
    fieldvalue VARCHAR,
    PRIMARY KEY (sid, fieldid),
    FOREIGN KEY (sid) REFERENCES users (sid) ON UPDATE CASCADE ON DELETE CASCADE
        DEFERRABLE
);


INSERT INTO users (sid, login, pwd) VALUES ('docker', 'docker', 'docker')
