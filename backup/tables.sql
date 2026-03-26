CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    fullname TEXT NOT NULL,
    role TEXT NOT NULL,
    active BOOLEAN DEFAULT true
);

CREATE TABLE refresh_tokens (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users (id),
    token TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL
);

CREATE TABLE solicitudes (
    solicitud_id SERIAL PRIMARY KEY,
    estatus_id INT NOT NULL,
    estatus_desc VARCHAR(50) NOT NULL,
    folio VARCHAR(20) UNIQUE NOT NULL,
    empleado_registro_id INT NOT NULL,
    nombre_empleado_registro VARCHAR(150) NOT NULL,
    departamento_id INT NOT NULL,
    departamento_desc VARCHAR(150) NOT NULL,
    ubicacion_desc VARCHAR(200),
    empleado_activo BOOLEAN DEFAULT true,
    tipo_solicitud_id INT NOT NULL,
    tipo_solicitud_desc VARCHAR(100) NOT NULL,
    descripcion TEXT NOT NULL,
    accion_correctiva TEXT,
    material_utilizado TEXT,
    fecha_registro TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    empleado_atendio_id INT,
    nombre_empleado_atendio VARCHAR(150),
    calidad VARCHAR(30),
    usuario VARCHAR(150),
    firma_valida BOOLEAN DEFAULT false,
    firma_tecnico_valida BOOLEAN DEFAULT false,
    programada BOOLEAN DEFAULT false,
    fecha_programada TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE servicios (
    id SERIAL PRIMARY KEY,
    service_id INT,
    service_desc TEXT NOT NULL
);

CREATE TABLE estatusactivo (
    EstatusActivoId SERIAL PRIMARY KEY,
    EstatusActivoDesc TEXT NOT NULL
);

CREATE TABLE dictamenes (
    dictamenid INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    solicitud_id INTEGER NOT NULL,
    consecutivodictamenid INTEGER NOT NULL,
    descripcion TEXT NOT NULL,
    folio VARCHAR(50) NOT NULL,
    caracteristicas TEXT NOT NULL,
    noserie VARCHAR(100) NOT NULL,
    resultados TEXT NOT NULL,
    EstatusActivoId INTEGER NOT NULL,
    fechahora TIMESTAMP NOT NULL,
    cancelado BOOLEAN NOT NULL DEFAULT FALSE,
    fechacancelacion TIMESTAMP,
    CONSTRAINT fk_dictamen_solicitud FOREIGN KEY (solicitud_id) REFERENCES solicitudes (solicitud_id),
    CONSTRAINT fk_dictamen_estatus FOREIGN KEY (EstatusActivoId) REFERENCES estatusactivo (EstatusActivoId)
);