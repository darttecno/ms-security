--liquibase formatted sql

--changeset andres.sanchez:V1.1.1 splitStatements:false runOnChange:true

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL
);

/*DROP TABLE IF EXISTS users;*/