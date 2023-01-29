insert into users(username, password, email, enabled, last_used)
values ('user1',
        '{pbkdf2@5.8}de1c83403bc7faa3e6c8ef2748ea1fa5131e7545c7d5b6f4949c475c5e55777ab26c5b8f4c13cf58b7266f859f73df8c',
        'user1@domain.com', true, to_timestamp(0));

insert into users(username, password, email, enabled, last_used)
values ('user2',
        '{pbkdf2@5.8}de1c83403bc7faa3e6c8ef2748ea1fa5131e7545c7d5b6f4949c475c5e55777ab26c5b8f4c13cf58b7266f859f73df8c',
        'user2@domain.com', true, to_timestamp(0));

insert into users(username, password, email, enabled, last_used)
values ('admin',
        '{pbkdf2@5.8}de1c83403bc7faa3e6c8ef2748ea1fa5131e7545c7d5b6f4949c475c5e55777ab26c5b8f4c13cf58b7266f859f73df8c',
        'admin@domain.com', true, to_timestamp(0));

insert into groups(group_name)
values ('ADMIN');
insert into groups(group_name)
values ('USER');

insert into group_authorities(group_id, authority)
values ((select id from groups where group_name = 'ADMIN'), 'ADMIN');
insert into group_authorities(group_id, authority)
values ((select id from groups where group_name = 'USER'), 'USER');

insert into authorities(username, authority)
values ('user1', 'USER');
insert into authorities(username, authority)
values ('user2', 'USER');
insert into authorities(username, authority)
values ('admin', 'ADMIN');
commit;