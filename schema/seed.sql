insert into oauth2.users(username, password, email, enabled, last_used)
values ('user1',
        '{bcrypt}$2a$10$/lHY/LC07uI64XMhL8nKDOx2K/MFoc.jQGteeEpZECYvt.VQZNyTC',
        'user1@domain.com', true, to_timestamp(0));

insert into oauth2.users(username, password, email, enabled, last_used)
values ('user2',
        '{bcrypt}$2a$10$/lHY/LC07uI64XMhL8nKDOx2K/MFoc.jQGteeEpZECYvt.VQZNyTC',
        'user2@domain.com', true, to_timestamp(0));

insert into oauth2.users(username, password, email, enabled, last_used)
values ('admin',
        '{bcrypt}$2a$10$/lHY/LC07uI64XMhL8nKDOx2K/MFoc.jQGteeEpZECYvt.VQZNyTC',
        'admin@domain.com', true, to_timestamp(0));

insert into oauth2.groups(group_name)
values ('ADMIN');
insert into oauth2.groups(group_name)
values ('USER');

insert into oauth2.group_authorities(group_id, authority)
values ((select id from oauth2.groups where group_name = 'ADMIN'), 'ADMIN');
insert into oauth2.group_authorities(group_id, authority)
values ((select id from oauth2.groups where group_name = 'USER'), 'USER');

insert into oauth2.authorities(username, authority)
values ('user1', 'USER');
insert into oauth2.authorities(username, authority)
values ('user2', 'USER');
insert into oauth2.authorities(username, authority)
values ('admin', 'ADMIN');
commit;