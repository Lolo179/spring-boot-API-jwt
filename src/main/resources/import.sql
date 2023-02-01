INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES ('luis', 'alvarado', 'primero@gmail.com', '2017-08-01', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES ('luis', 'alvarado', 'primero@gmail.com', '2017-08-01', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES ('luis', 'alvarado', 'primero@gmail.com', '2017-08-01', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES ('luis', 'alvarado', 'primero@gmail.com', '2017-08-01', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES ('luis', 'alvarado', 'primero@gmail.com', '2017-08-01', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES ('luis', 'alvarado', 'primero@gmail.com', '2017-08-01', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES ('luis', 'alvarado', 'primero@gmail.com', '2017-08-01', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES ('luis', 'alvarado', 'primero@gmail.com', '2017-08-01', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES ('luis', 'alvarado', 'primero@gmail.com', '2017-08-01', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES ('luis', 'alvarado', 'primero@gmail.com', '2017-08-01', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES ('luis', 'alvarado', 'primero@gmail.com', '2017-08-01', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES ('luis', 'alvarado', 'primero@gmail.com', '2017-08-01', '');
INSERT INTO clientes (nombre, apellido, email, create_at, foto) VALUES ('luis', 'alvarado', 'primero@gmail.com', '2017-08-01', '');

INSERT INTO productos (nombre, precio, create_at) VALUES ('panasonic Pantalla LCD', 259990, NOW());
INSERT INTO productos (nombre, precio, create_at) VALUES ('Sony camara digital DSC-W320B', 65442, NOW());
INSERT INTO productos (nombre, precio, create_at) VALUES ('Apple iphone 13', 327654, NOW());
INSERT INTO productos (nombre, precio, create_at) VALUES ('Razer mouse deathrader', 98314, NOW());
INSERT INTO productos (nombre, precio, create_at) VALUES ('Nfortec disipador', 65731, NOW());
INSERT INTO productos (nombre, precio, create_at) VALUES ('Apple airpods 2 gen', 342713, NOW());

INSERT INTO facturas (descripcion, observacion, cliente_id, create_at) VALUES('Factura equipos de oficina', null,1,NOW());
INSERT INTO facturas_items(cantidad,factura_id,producto_id) VALUES(1,1,1);
INSERT INTO facturas_items(cantidad,factura_id,producto_id) VALUES(2,1,4);
INSERT INTO facturas_items(cantidad,factura_id,producto_id) VALUES(1,1,5);
INSERT INTO facturas_items(cantidad,factura_id,producto_id) VALUES(1,1,6);

INSERT INTO users (username, password, enabled) VALUES ('lolo','$2a$10$7XJPBaY/DrnKAyPOZqcOH.jYbGl5KVXWhvec7qYA/Zi1FvM/in/g.',1);
INSERT INTO users (username, password, enabled) VALUES ('admin','$2a$10$NT2hEqKKcHKqnAdVlaGXPuswC9G6o5bHLmE3/fxcemvFRRuP4o9pm',1);

INSERT INTO authorities (user_id, authority) VALUES ('1','ROLE_USER');
INSERT INTO authorities (user_id, authority) VALUES ('2','ROLE_USER');
INSERT INTO authorities (user_id, authority) VALUES ('2','ROLE_ADMIN');