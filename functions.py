def map_solicitud(row: dict) -> dict:
    return {
        "solicitudId": row["solicitud_id"],

        "estatus": {
            "estatusId": row["estatus_id"],
            "estatusDesc": row["estatus_desc"],
        },

        "consecutivo": {
            "folio": row["folio"],
        },

        "registro": {
            "empleadoId": row["empleado_registro_id"],
            "departamentos": {
                "departamentoId": row["departamento_id"],
                "departamentoDesc": row["departamento_desc"],
            },
            "ubicacionDesc": row["ubicacion_desc"],
            "estatus": row["empleado_activo"],
            "nombreEmpleado": row["nombre_empleado_registro"],
        },

        "tipoSolicitud": {
            "tipoSolicitudId": row["tipo_solicitud_id"],
            "tipoSolicitudDesc": row["tipo_solicitud_desc"],
        },

        "descripcion": row["descripcion"],
        "accionCorrectiva": row["accion_correctiva"],
        "materialUtilizado": row["material_utilizado"],

        "fechaRegistro": row["fecha_registro"],

        "atendio": {
            "empleadoId": row["empleado_atendio_id"],
            "nombreEmpleado": row["nombre_empleado_atendio"],
        },

        "calidad": row["calidad"],
        "usuario": row["usuario"],

        "firmaValida": row["firma_valida"],
        "firmaTecnicoValida": row["firma_tecnico_valida"],

        "programada": row["programada"],
        "fechaProgramada": row["fecha_programada"],
    }

def map_status_dictamenes(row: dict) -> dict:
    return {
        "estatusActivoId": row["estatusactivoid"],
        "estatusActivoDesc": row["estatusactivodesc"],
    }

def map_dictamen(row: dict) -> dict:
    return {
        "cancelado": row["cancelado"],
        "dictamenId": row["dictamenid"],
        "fechaHora": row["fechahora"],
        "consecutivo": {
            "folio": row["folio"]
        },
    }