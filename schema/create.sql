drop table authorities;
drop table users;

create table users
(
    username  varchar(50)  not null primary key,
    email     varchar(100) not null unique,
    password  varchar(128) not null,
    enabled   boolean      not null,
    last_used timestamp
);

create table authorities
(
    username  varchar(50) not null,
    authority varchar(50) not null,
    constraint fk_authorities_users foreign key (username) references users (username)
);
create unique index ix_auth_username on authorities (username, authority);

create table groups
(
    id         serial primary key,
    group_name varchar(50) not null
);

create table group_authorities
(
    group_id  serial primary key,
    authority varchar(50) not null,
    constraint fk_group_authorities_group foreign key (group_id) references groups (id)
);

create table group_members
(
    id       serial primary key,
    username varchar(50) not null,
    group_id bigint      not null,
    constraint fk_group_members_group foreign key (group_id) references groups (id)
);