create table refresh_tokens
(
    id           int auto_increment
        primary key,
    content      varchar(100) not null,
    valid_until  timestamp    not null,
    access_token varchar(300) not null,
    username     varchar(100) not null
);

create table roles
(
    id   int auto_increment
        primary key,
    name varchar(10) null
);

create table accounts
(
    id       int auto_increment
        primary key,
    username varchar(100)                 not null,
    password varchar(100)                 not null,
    email    varchar(100)                 not null,
    role_id  int                          null,
    name     varchar(200) charset utf8mb3 null,
    constraint accounts_ibfk_1
        foreign key (role_id) references roles (id)
);

create index accounts_index_email
    on accounts (email);

create index role_id
    on accounts (role_id);

