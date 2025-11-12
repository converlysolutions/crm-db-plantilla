


SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;


CREATE EXTENSION IF NOT EXISTS "pg_cron" WITH SCHEMA "pg_catalog";






CREATE EXTENSION IF NOT EXISTS "pg_net" WITH SCHEMA "extensions";






COMMENT ON SCHEMA "public" IS 'standard public schema';



CREATE EXTENSION IF NOT EXISTS "pg_graphql" WITH SCHEMA "graphql";






CREATE EXTENSION IF NOT EXISTS "pg_stat_statements" WITH SCHEMA "extensions";






CREATE EXTENSION IF NOT EXISTS "pgcrypto" WITH SCHEMA "extensions";






CREATE EXTENSION IF NOT EXISTS "supabase_vault" WITH SCHEMA "vault";






CREATE EXTENSION IF NOT EXISTS "unaccent" WITH SCHEMA "public";






CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA "extensions";






CREATE TYPE "public"."estado_cliente" AS ENUM (
    'desistido',
    'stand by',
    'procesando',
    'activo',
    'rechazado'
);


ALTER TYPE "public"."estado_cliente" OWNER TO "postgres";


CREATE TYPE "public"."estado_contrato" AS ENUM (
    'activo',
    'pendiente',
    'vencido',
    'resuelto'
);


ALTER TYPE "public"."estado_contrato" OWNER TO "postgres";


CREATE TYPE "public"."estado_factura" AS ENUM (
    'borrador',
    'emitida',
    'pagada',
    'anulada'
);


ALTER TYPE "public"."estado_factura" OWNER TO "postgres";


CREATE TYPE "public"."rol_usuario" AS ENUM (
    'administrador',
    'comercial',
    'cliente'
);


ALTER TYPE "public"."rol_usuario" OWNER TO "postgres";


CREATE TYPE "public"."tarifa_acceso" AS ENUM (
    '2.0',
    '3.0',
    '6.1',
    'RL1',
    'RL2',
    'RL3',
    'RL4'
);


ALTER TYPE "public"."tarifa_acceso" OWNER TO "postgres";


CREATE TYPE "public"."tarifa_electrica" AS ENUM (
    '2.0TD',
    '3.0TD',
    '6.1TD'
);


ALTER TYPE "public"."tarifa_electrica" OWNER TO "postgres";


CREATE TYPE "public"."tipo_cliente" AS ENUM (
    'persona',
    'sociedad'
);


ALTER TYPE "public"."tipo_cliente" OWNER TO "postgres";


CREATE TYPE "public"."tipo_documento" AS ENUM (
    'factura',
    'contrato',
    'otro'
);


ALTER TYPE "public"."tipo_documento" OWNER TO "postgres";


CREATE TYPE "public"."tipo_empresa" AS ENUM (
    'comercializadora',
    'openenergies'
);


ALTER TYPE "public"."tipo_empresa" OWNER TO "postgres";


CREATE TYPE "public"."tipo_energia" AS ENUM (
    'luz',
    'gas'
);


ALTER TYPE "public"."tipo_energia" OWNER TO "postgres";


CREATE TYPE "public"."tipo_factura_enum" AS ENUM (
    'Luz',
    'Gas'
);


ALTER TYPE "public"."tipo_factura_enum" OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."agenda_eventos_set_creator"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
  -- Si no se proporcionó un nombre, lo buscamos en usuarios_app
  IF NEW.creado_por_nombre IS NULL THEN
    SELECT COALESCE(nombre, email) INTO NEW.creado_por_nombre
    FROM public.usuarios_app 
    WHERE user_id = NEW.user_id; -- NEW.user_id lo pone Supabase automáticamente
  END IF;
  
  -- Si no se proporcionó un email, lo buscamos
  IF NEW.creado_por_email IS NULL THEN
    SELECT email INTO NEW.creado_por_email
    FROM public.usuarios_app 
    WHERE user_id = NEW.user_id;
  END IF;
  
  -- Devolvemos la fila modificada para que se inserte
  RETURN NEW;
END $$;


ALTER FUNCTION "public"."agenda_eventos_set_creator"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."belongs_to_empresa"("eid" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE
    AS $$
  select public.is_admin() or public.current_user_empresa_id() = eid;
$$;


ALTER FUNCTION "public"."belongs_to_empresa"("eid" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."can_access_cliente"("id_cliente" "uuid") RETURNS boolean
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
    cliente_exists boolean;
BEGIN
    -- Comprobación robusta contra NULL o IDs inválidos
    IF id_cliente IS NULL THEN
        RETURN false;
    END IF;

    -- Comprueba si el cliente existe (esta consulta no activará RLS)
    SELECT EXISTS (SELECT 1 FROM public.clientes WHERE id = id_cliente) INTO cliente_exists;
    IF NOT cliente_exists THEN
        RETURN false;
    END IF;

    -- Lógica de permisos original (ahora segura)
    IF current_user_role() = 'administrador' THEN
        RETURN true;
    END IF;

    IF current_user_role() = 'comercial' THEN
        RETURN EXISTS (
            SELECT 1 FROM public.asignaciones_comercial
            WHERE asignaciones_comercial.cliente_id = id_cliente AND asignaciones_comercial.comercial_user_id = auth.uid()
        );
    END IF;
    
    IF current_user_role() = 'cliente' THEN
        RETURN EXISTS (
            SELECT 1 FROM public.contactos_cliente
            WHERE contactos_cliente.cliente_id = id_cliente AND contactos_cliente.user_id = auth.uid()
        );
    END IF;

    RETURN false;
END;
$$;


ALTER FUNCTION "public"."can_access_cliente"("id_cliente" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."can_access_contrato"("coid" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  SELECT public.is_admin()
  OR public.can_access_punto(
        (SELECT c.punto_id FROM public.contratos c WHERE c.id = coid)
     );
$$;


ALTER FUNCTION "public"."can_access_contrato"("coid" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."can_access_factura"("fid" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE
    AS $$
  select public.is_admin()
  or public.can_access_cliente(
        (select f.cliente_id from public.facturas f where f.id = fid)
     );
$$;


ALTER FUNCTION "public"."can_access_factura"("fid" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."can_access_punto"("pid" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  SELECT public.is_admin()
  OR public.can_access_cliente(
        (SELECT p.cliente_id FROM public.puntos_suministro p WHERE p.id = pid)
     );
$$;


ALTER FUNCTION "public"."can_access_punto"("pid" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."current_user_empresa_id"() RETURNS "uuid"
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$ SELECT empresa_id FROM public.usuarios_app WHERE user_id = auth.uid() $$;


ALTER FUNCTION "public"."current_user_empresa_id"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."current_user_role"() RETURNS "text"
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  SELECT rol::text FROM usuarios_app WHERE user_id = auth.uid() LIMIT 1
$$;


ALTER FUNCTION "public"."current_user_role"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."delete_contrato"("contrato_id_to_delete" "uuid") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
BEGIN
  -- Intentamos borrar el contrato directamente
  DELETE FROM public.contratos
  WHERE id = contrato_id_to_delete;

  -- Comprobamos si realmente se borró algo
  IF NOT FOUND THEN
     RAISE WARNING 'No se encontró o no se pudo eliminar ningún contrato con ID %.', contrato_id_to_delete;
     -- Puedes cambiar a RAISE EXCEPTION si prefieres un error
     -- RAISE EXCEPTION 'No se encontró o no se pudo eliminar el contrato con ID %.', contrato_id_to_delete;
  END IF;

EXCEPTION
  -- Capturamos errores específicos, como violación de FK
  WHEN foreign_key_violation THEN
    RAISE EXCEPTION 'No se pudo borrar el contrato (ID: %). Aún tiene datos asociados (documentos, notificaciones, etc.).', contrato_id_to_delete
    USING HINT = 'Elimina primero los datos asociados o configura ON DELETE CASCADE en las tablas correspondientes.';
  WHEN others THEN
    -- Para cualquier otro error
    RAISE EXCEPTION 'Error inesperado al borrar el contrato (ID: %): %', contrato_id_to_delete, SQLERRM;
END;
$$;


ALTER FUNCTION "public"."delete_contrato"("contrato_id_to_delete" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."delete_punto_suministro"("punto_id_to_delete" "uuid") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
BEGIN
  -- Intentamos borrar el punto de suministro directamente
  DELETE FROM public.puntos_suministro
  WHERE id = punto_id_to_delete;

  -- Comprobamos si realmente se borró algo
  IF NOT FOUND THEN
     RAISE WARNING 'No se encontró o no se pudo eliminar ningún punto con ID %.', punto_id_to_delete;
     -- Considera lanzar EXCEPTION si prefieres que sea un error más grave
     RAISE EXCEPTION 'No se encontró o no se pudo eliminar el punto con ID %.', punto_id_to_delete;
  END IF;

EXCEPTION
  -- Capturamos errores específicos, como violación de FK
  WHEN foreign_key_violation THEN
    RAISE EXCEPTION 'No se pudo borrar el punto (ID: %). Aún tiene datos asociados (contratos, documentos, etc.).', punto_id_to_delete
    USING HINT = 'Elimina primero los datos asociados o configura ON DELETE CASCADE en las tablas correspondientes.';
  WHEN others THEN
    -- Para cualquier otro error
    RAISE EXCEPTION 'Error inesperado al borrar el punto de suministro (ID: %): %', punto_id_to_delete, SQLERRM;
END;
$$;


ALTER FUNCTION "public"."delete_punto_suministro"("punto_id_to_delete" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_agenda_items"("fecha_query_inicio" timestamp with time zone, "fecha_query_fin" timestamp with time zone) RETURNS TABLE("id" "uuid", "titulo" "text", "fecha_inicio" timestamp with time zone, "fecha_fin" timestamp with time zone, "color" "text", "etiqueta" "text", "tipo_evento" "text", "es_editable" boolean, "cliente_id_relacionado" "uuid", "creador_nombre" "text")
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
    auth_user_id uuid := auth.uid();
    auth_role    TEXT := current_user_role();
    my_empresa   uuid := get_my_empresa_id();
BEGIN
    -- 1) Eventos manuales
    RETURN QUERY
    SELECT
        e.id,
        e.titulo,
        e.fecha_inicio,
        e.fecha_fin,
        e.color,
        e.etiqueta,
        'evento'::text AS tipo_evento,
        (e.user_id = auth_user_id OR auth_role = 'administrador') AS es_editable,
        NULL::uuid AS cliente_id_relacionado,
        COALESCE(e.creado_por_nombre, 'Usuario desconocido') AS creador_nombre 
    FROM public.agenda_eventos e
    WHERE
        e.fecha_inicio <= fecha_query_fin
        AND (e.fecha_fin IS NULL OR e.fecha_fin >= fecha_query_inicio)
        AND (
            auth_role = 'administrador'
            OR (auth_role = 'comercial' AND e.user_id = auth_user_id)
        )
        AND (auth_role = 'administrador' OR e.empresa_id = my_empresa);

    -- 2) Renovaciones (Esta parte no cambia)
    RETURN QUERY
    SELECT
        c.id,
        'Vencimiento: ' || cl.nombre AS titulo,
        c.fecha_fin::timestamptz    AS fecha_inicio,
        NULL::timestamptz           AS fecha_fin,
        'var(--danger-color, #DC2626)' AS color,
        'Renovación'                AS etiqueta,
        'renovacion'                AS tipo_evento,
        false                       AS es_editable,
        ps.cliente_id               AS cliente_id_relacionado,
        NULL::text AS creador_nombre 
    FROM public.contratos c
    JOIN public.puntos_suministro ps ON ps.id = c.punto_id
    JOIN public.clientes          cl ON cl.id = ps.cliente_id
    WHERE
        c.fecha_fin IS NOT NULL
        AND c.fecha_fin BETWEEN fecha_query_inicio AND fecha_query_fin
        AND (auth_role = 'administrador' OR cl.empresa_id = my_empresa)
        AND (
            auth_role = 'administrador'
            OR EXISTS (
                SELECT 1
                FROM public.asignaciones_comercial ac
                WHERE ac.cliente_id = ps.cliente_id
                  AND ac.comercial_user_id = auth_user_id
            )
        );
END;
$$;


ALTER FUNCTION "public"."get_agenda_items"("fecha_query_inicio" timestamp with time zone, "fecha_query_fin" timestamp with time zone) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_all_root_documents"() RETURNS TABLE("cliente_id" "uuid", "cliente_nombre" "text", "item_name" "text", "is_folder" boolean, "full_path" "text", "visible_para_cliente" boolean)
    LANGUAGE "sql"
    AS $_$
  -- 1. Obtener todos los archivos en la raíz de un cliente
  SELECT
    d.cliente_id,
    c.nombre AS cliente_nombre,
    d.nombre_archivo AS item_name,
    false AS is_folder,
    d.ruta_storage AS full_path,
    d.visible_para_cliente -- <-- Columna añadida
  FROM public.documentos d
  JOIN public.clientes c ON d.cliente_id = c.id
  WHERE
    -- 'clientes/[uuid]/archivo.pdf' (no contiene más '/')
    d.ruta_storage ~ '^clientes\/[a-f0-9-]+\/[^/]+$'

  UNION ALL

  -- 2. Obtener todas las "carpetas" en la raíz
  SELECT
    d.cliente_id,
    c.nombre AS cliente_nombre,
    -- Extrae el nombre de la carpeta de la ruta
    -- 'clientes/[uuid]/[carpeta_nombre]/...' -> 'carpeta_nombre'
    split_part(d.ruta_storage, '/', 3) AS item_name,
    true AS is_folder,
    -- La "ruta" de la carpeta es solo su nombre
    split_part(d.ruta_storage, '/', 3) AS full_path,
    -- Una carpeta se considera "visible" si *al menos un*
    -- archivo dentro de ella es visible.
    bool_or(d.visible_para_cliente) AS visible_para_cliente -- <-- Columna añadida
  FROM public.documentos d
  JOIN public.clientes c ON d.cliente_id = c.id
  WHERE
    -- 'clientes/[uuid]/[carpeta_nombre]/archivo.pdf' (contiene 2 o más '/')
    d.ruta_storage ~ '^clientes\/[a-f0-9-]+\/.+\/.+$'
  GROUP BY
    d.cliente_id, c.nombre, item_name;
$_$;


ALTER FUNCTION "public"."get_all_root_documents"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_my_empresa_id"() RETURNS "uuid"
    LANGUAGE "sql" STABLE
    AS $$
  SELECT empresa_id FROM public.usuarios_app WHERE user_id = auth.uid()
$$;


ALTER FUNCTION "public"."get_my_empresa_id"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."is_admin"() RETURNS boolean
    LANGUAGE "sql" STABLE
    AS $$ SELECT public.current_user_role() = 'administrador' $$;


ALTER FUNCTION "public"."is_admin"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."is_valid_uuid"("uuid_text" "text") RETURNS boolean
    LANGUAGE "plpgsql" IMMUTABLE
    AS $_$
BEGIN
  -- Esta regex valida el formato estándar de un UUID (ej: a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11)
  RETURN uuid_text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';
EXCEPTION
  WHEN OTHERS THEN
    RETURN FALSE;
END;
$_$;


ALTER FUNCTION "public"."is_valid_uuid"("uuid_text" "text") OWNER TO "postgres";

SET default_tablespace = '';

SET default_table_access_method = "heap";


CREATE TABLE IF NOT EXISTS "public"."clientes" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "empresa_id" "uuid" NOT NULL,
    "tipo" "public"."tipo_cliente" NOT NULL,
    "nombre" "text" NOT NULL,
    "dni" "text",
    "cif" "text",
    "email_facturacion" "text",
    "creado_en" timestamp with time zone DEFAULT "now"(),
    "estado" "public"."estado_cliente" DEFAULT 'stand by'::"public"."estado_cliente" NOT NULL
);


ALTER TABLE "public"."clientes" OWNER TO "postgres";


COMMENT ON TABLE "public"."clientes" IS 'Clientes finales (titulares) de cada empresa/comercializadora. Pueden ser persona (DNI) o sociedad (CIF).';



CREATE OR REPLACE FUNCTION "public"."search_clientes"("search_text" "text") RETURNS SETOF "public"."clientes"
    LANGUAGE "sql" STABLE
    SET "search_path" TO 'public'
    AS $$
  select c.*
  from public.clientes c
  left join public.empresas e on e.id = c.empresa_id
  where
    coalesce(search_text, '') = ''
    or unaccent(c.nombre) ilike '%' || unaccent(search_text) || '%'
    or unaccent(coalesce(c.dni,'')) ilike '%' || unaccent(search_text) || '%'
    or unaccent(coalesce(c.cif,'')) ilike '%' || unaccent(search_text) || '%'
    or unaccent(e.nombre) ilike '%' || unaccent(search_text) || '%'
  order by c.creado_en desc
$$;


ALTER FUNCTION "public"."search_clientes"("search_text" "text") OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."contratos" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "punto_id" "uuid" NOT NULL,
    "comercializadora_id" "uuid" NOT NULL,
    "oferta" "text",
    "fecha_inicio" "date" NOT NULL,
    "fecha_fin" "date",
    "aviso_renovacion" boolean DEFAULT false NOT NULL,
    "fecha_aviso" "date",
    "estado" "public"."estado_contrato" DEFAULT 'activo'::"public"."estado_contrato" NOT NULL
);


ALTER TABLE "public"."contratos" OWNER TO "postgres";


COMMENT ON TABLE "public"."contratos" IS 'Contratos asociados a un punto de suministro: vigencia, comercializadora, oferta y aviso de renovación.';



CREATE OR REPLACE FUNCTION "public"."search_contratos"("search_text" "text", "p_cliente_id" "uuid" DEFAULT NULL::"uuid") RETURNS SETOF "public"."contratos"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
    RETURN QUERY
    SELECT con.*
    FROM contratos con
    LEFT JOIN empresas com ON con.comercializadora_id = com.id
    LEFT JOIN puntos_suministro ps ON con.punto_id = ps.id
    WHERE
        -- Filtro opcional por cliente_id (si se usa el componente en la ficha de un cliente)
        (p_cliente_id IS NULL OR ps.cliente_id = p_cliente_id)
        AND
        -- Filtro de búsqueda por texto
        (
            search_text IS NULL OR search_text = '' OR
            com.nombre ILIKE '%' || search_text || '%' -- Busca por nombre de comercializadora
            OR ps.cups ILIKE '%' || search_text || '%'   -- Busca por CUPS
        );
END;
$$;


ALTER FUNCTION "public"."search_contratos"("search_text" "text", "p_cliente_id" "uuid") OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."puntos_suministro" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "cliente_id" "uuid" NOT NULL,
    "titular" "text" NOT NULL,
    "direccion" "text" NOT NULL,
    "cups" "text" NOT NULL,
    "tarifa_acceso" "text" NOT NULL,
    "potencia_contratada_kw" numeric(10,3),
    "consumo_anual_kwh" numeric(14,3),
    "localidad" "text",
    "provincia" "text",
    "tipo_factura" "public"."tipo_factura_enum"
);


ALTER TABLE "public"."puntos_suministro" OWNER TO "postgres";


COMMENT ON TABLE "public"."puntos_suministro" IS 'Puntos de suministro del cliente (CUPS), con dirección, potencia y consumo anual para comparativas.';



COMMENT ON COLUMN "public"."puntos_suministro"."localidad" IS 'Localidad donde se encuentra el punto de suministro (del Excel)';



COMMENT ON COLUMN "public"."puntos_suministro"."provincia" IS 'Provincia donde se encuentra el punto de suministro (del Excel)';



COMMENT ON COLUMN "public"."puntos_suministro"."tipo_factura" IS 'Tipo de factura asociado al punto de suministro (Luz o Gas)';



CREATE OR REPLACE FUNCTION "public"."search_puntos_suministro"("search_text" "text", "p_cliente_id" "uuid" DEFAULT NULL::"uuid") RETURNS SETOF "public"."puntos_suministro"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  RETURN QUERY
  SELECT ps.*
  FROM puntos_suministro ps
  LEFT JOIN clientes c ON ps.cliente_id = c.id
  WHERE
    -- Primero, se asegura de filtrar por cliente si se proporciona un ID
    (p_cliente_id IS NULL OR ps.cliente_id = p_cliente_id)
    AND
    -- Segundo, busca el texto en todos los campos relevantes
    (
      search_text IS NULL OR search_text = '' OR
      ps.titular ILIKE '%' || search_text || '%'
      OR ps.cups ILIKE '%' || search_text || '%'
      OR ps.direccion ILIKE '%' || search_text || '%'
      OR c.nombre ILIKE '%' || search_text || '%' -- Aquí está la búsqueda en la tabla de clientes
    );
END;
$$;


ALTER FUNCTION "public"."search_puntos_suministro"("search_text" "text", "p_cliente_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."set_folder_visibility"("p_cliente_id" "uuid", "p_folder_path" "text", "p_is_visible" boolean) RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
    v_path_prefix text;
    admin_rol text;
BEGIN
    -- Comprobación de seguridad: solo los admins pueden ejecutar esto
    SELECT rol INTO admin_rol FROM public.usuarios_app WHERE user_id = auth.uid();
    IF admin_rol != 'administrador' THEN
        RAISE EXCEPTION 'Acción no autorizada. Solo los administradores pueden cambiar la visibilidad.';
    END IF;

    -- Construye el prefijo de ruta: 'clientes/[cliente_id]/'
    v_path_prefix := 'clientes/' || p_cliente_id::text || '/';
    
    -- Añade la ruta de la subcarpeta si no es la raíz
    IF p_folder_path IS NOT NULL AND p_folder_path != '' THEN
        v_path_prefix := v_path_prefix || p_folder_path || '/';
    END IF;
    
    -- Actualiza todos los documentos que COMIENZAN con esa ruta
    UPDATE public.documentos
    SET visible_para_cliente = p_is_visible
    WHERE cliente_id = p_cliente_id
      AND ruta_storage LIKE v_path_prefix || '%';
END;
$$;


ALTER FUNCTION "public"."set_folder_visibility"("p_cliente_id" "uuid", "p_folder_path" "text", "p_is_visible" boolean) OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."agenda_eventos" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid" DEFAULT "auth"."uid"(),
    "empresa_id" "uuid" NOT NULL,
    "titulo" "text" NOT NULL,
    "fecha_inicio" timestamp with time zone NOT NULL,
    "fecha_fin" timestamp with time zone,
    "color" "text",
    "etiqueta" "text",
    "creado_en" timestamp with time zone DEFAULT "now"(),
    "creado_por_nombre" "text",
    "creado_por_email" "text"
);

ALTER TABLE ONLY "public"."agenda_eventos" FORCE ROW LEVEL SECURITY;


ALTER TABLE "public"."agenda_eventos" OWNER TO "postgres";


COMMENT ON COLUMN "public"."agenda_eventos"."creado_por_nombre" IS 'Nombre del usuario que creó el evento (snapshot en el momento de la creación).';



COMMENT ON COLUMN "public"."agenda_eventos"."creado_por_email" IS 'Email del usuario que creó el evento (snapshot en el momento de la creación).';



CREATE TABLE IF NOT EXISTS "public"."asignaciones_comercial" (
    "cliente_id" "uuid" NOT NULL,
    "comercial_user_id" "uuid" NOT NULL
);


ALTER TABLE "public"."asignaciones_comercial" OWNER TO "postgres";


COMMENT ON TABLE "public"."asignaciones_comercial" IS 'Define la cartera: qué clientes gestiona cada usuario con rol comercial (para limitar su alcance).';



CREATE TABLE IF NOT EXISTS "public"."chat_history" (
    "id" integer NOT NULL,
    "user_id" character varying(255) NOT NULL,
    "message" "jsonb" NOT NULL
);


ALTER TABLE "public"."chat_history" OWNER TO "postgres";


CREATE SEQUENCE IF NOT EXISTS "public"."chat_history_id_seq"
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE "public"."chat_history_id_seq" OWNER TO "postgres";


ALTER SEQUENCE "public"."chat_history_id_seq" OWNED BY "public"."chat_history"."id";



CREATE TABLE IF NOT EXISTS "public"."comparativas" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "creado_por_user_id" "uuid" NOT NULL,
    "cliente_id" "uuid",
    "punto_id" "uuid",
    "solicitada_en" timestamp with time zone DEFAULT "now"(),
    "resumen_resultado" "text",
    "ruta_pdf" "text",
    "prospecto_nombre" "text",
    "prospecto_contacto" "text"
);


ALTER TABLE "public"."comparativas" OWNER TO "postgres";


COMMENT ON TABLE "public"."comparativas" IS 'Histórico de comparativas de precios. Admite cliente/punto existentes o prospectos (sin alta previa) y ruta a PDF si se generó.';



CREATE TABLE IF NOT EXISTS "public"."consumos" (
    "id" bigint NOT NULL,
    "punto_id" "uuid" NOT NULL,
    "periodo_inicio" "date" NOT NULL,
    "periodo_fin" "date" NOT NULL,
    "kwh" numeric(14,3) NOT NULL,
    "precio_kwh" numeric(12,6)
);


ALTER TABLE "public"."consumos" OWNER TO "postgres";


COMMENT ON TABLE "public"."consumos" IS 'Lecturas de consumo importadas (SIPS) por punto de suministro y periodo.';



CREATE SEQUENCE IF NOT EXISTS "public"."consumos_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE "public"."consumos_id_seq" OWNER TO "postgres";


ALTER SEQUENCE "public"."consumos_id_seq" OWNED BY "public"."consumos"."id";



CREATE TABLE IF NOT EXISTS "public"."contactos_cliente" (
    "cliente_id" "uuid" NOT NULL,
    "user_id" "uuid" NOT NULL
);


ALTER TABLE "public"."contactos_cliente" OWNER TO "postgres";


COMMENT ON TABLE "public"."contactos_cliente" IS 'Asocia usuarios con rol cliente a su ficha de cliente para acceso al Área de cliente.';



CREATE TABLE IF NOT EXISTS "public"."documentos" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "cliente_id" "uuid",
    "punto_id" "uuid",
    "contrato_id" "uuid",
    "factura_id" "uuid",
    "tipo" "text" NOT NULL,
    "ruta_storage" "text" NOT NULL,
    "nombre_archivo" "text",
    "mime_type" "text",
    "tamano_bytes" bigint,
    "subido_por_user_id" "uuid",
    "subido_en" timestamp with time zone DEFAULT "now"(),
    "visible_para_cliente" boolean DEFAULT false NOT NULL
);


ALTER TABLE "public"."documentos" OWNER TO "postgres";


COMMENT ON TABLE "public"."documentos" IS 'Metadatos de PDFs (facturas, contratos, etc.) y su ubicación en almacenamiento para listados/descargas y trazabilidad.';



CREATE TABLE IF NOT EXISTS "public"."empresas" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "nombre" "text" NOT NULL,
    "cif" "text",
    "tipo" "public"."tipo_empresa" NOT NULL,
    "creada_en" timestamp with time zone DEFAULT "now"(),
    "is_archived" boolean DEFAULT false NOT NULL,
    "archived_at" timestamp with time zone,
    "logo_url" "text"
);


ALTER TABLE "public"."empresas" OWNER TO "postgres";


COMMENT ON TABLE "public"."empresas" IS 'Empresas que usan el CRM: Open Energies y cada comercializadora cliente. Sirve para separar datos por empresa.';



CREATE TABLE IF NOT EXISTS "public"."facturas" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "cliente_id" "uuid" NOT NULL,
    "fecha_emision" "date" NOT NULL,
    "numero" "text" NOT NULL,
    "total_eur" numeric(14,2) NOT NULL,
    "moneda" "text" DEFAULT 'EUR'::"text" NOT NULL,
    "estado" "public"."estado_factura" DEFAULT 'emitida'::"public"."estado_factura" NOT NULL,
    "remesa_id" "uuid"
);


ALTER TABLE "public"."facturas" OWNER TO "postgres";


COMMENT ON TABLE "public"."facturas" IS 'Facturas emitidas al cliente (similar a Contasimple): fecha, número, total, estado.';



COMMENT ON COLUMN "public"."facturas"."remesa_id" IS 'Si no es nulo, indica la remesa a la que pertenece esta factura. Relación 0..1 (una factura no está en más de una remesa).';



CREATE TABLE IF NOT EXISTS "public"."lineas_factura" (
    "id" bigint NOT NULL,
    "factura_id" "uuid" NOT NULL,
    "descripcion" "text" NOT NULL,
    "cantidad" numeric(12,3) NOT NULL,
    "precio_unitario" numeric(12,6) NOT NULL,
    "tipo_impuesto" numeric(5,2) DEFAULT 21.00 NOT NULL
);


ALTER TABLE "public"."lineas_factura" OWNER TO "postgres";


COMMENT ON TABLE "public"."lineas_factura" IS 'Conceptos que componen cada factura: cantidades, precios e impuestos.';



CREATE SEQUENCE IF NOT EXISTS "public"."lineas_factura_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE "public"."lineas_factura_id_seq" OWNER TO "postgres";


ALTER SEQUENCE "public"."lineas_factura_id_seq" OWNED BY "public"."lineas_factura"."id";



CREATE TABLE IF NOT EXISTS "public"."notificaciones" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "empresa_id" "uuid" NOT NULL,
    "contrato_id" "uuid",
    "cliente_id" "uuid",
    "tipo" "text" DEFAULT 'contrato_renovacion'::"text" NOT NULL,
    "asunto" "text" NOT NULL,
    "cuerpo" "text" NOT NULL,
    "destinatarios_emails" "text"[] NOT NULL,
    "canal" "text" DEFAULT 'email'::"text" NOT NULL,
    "programada_para" timestamp with time zone NOT NULL,
    "estado" "text" DEFAULT 'pendiente'::"text" NOT NULL,
    "enviada_en" timestamp with time zone,
    "error_texto" "text",
    "creada_por_user_id" "uuid",
    "creada_en" timestamp with time zone DEFAULT "now"(),
    "user_id_destinatario" "uuid",
    "leida" boolean DEFAULT false NOT NULL,
    "agenda_evento_id" "uuid"
);


ALTER TABLE "public"."notificaciones" OWNER TO "postgres";


COMMENT ON TABLE "public"."notificaciones" IS 'Programación y registro de avisos (principalmente renovaciones). Mantiene destinatarios, estado y trazabilidad del envío.';



CREATE TABLE IF NOT EXISTS "public"."precios_energia" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "empresa_id" "uuid" NOT NULL,
    "tarifa" "public"."tarifa_electrica" NOT NULL,
    "fecha_mes" "date" NOT NULL,
    "precio_energia_p1" numeric(10,6),
    "precio_energia_p2" numeric(10,6),
    "precio_energia_p3" numeric(10,6),
    "precio_energia_p4" numeric(10,6),
    "precio_energia_p5" numeric(10,6),
    "precio_energia_p6" numeric(10,6),
    "creado_en" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."precios_energia" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."precios_potencia" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "empresa_id" "uuid" NOT NULL,
    "tarifa" "public"."tarifa_electrica" NOT NULL,
    "año" integer NOT NULL,
    "precio_potencia_p1" numeric(10,6),
    "precio_potencia_p2" numeric(10,6),
    "precio_potencia_p3" numeric(10,6),
    "precio_potencia_p4" numeric(10,6),
    "precio_potencia_p5" numeric(10,6),
    "precio_potencia_p6" numeric(10,6),
    "creado_en" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."precios_potencia" OWNER TO "postgres";


COMMENT ON TABLE "public"."precios_potencia" IS 'Almacena los precios de potencia (€/kW/año) por empresa, tarifa y año.';



COMMENT ON COLUMN "public"."precios_potencia"."año" IS 'Año de vigencia del precio (Ej: 2024, 2025).';



CREATE TABLE IF NOT EXISTS "public"."remesas" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "empresa_id" "uuid" NOT NULL,
    "creada_en" timestamp with time zone DEFAULT "now"(),
    "estado" "text" DEFAULT 'borrador'::"text" NOT NULL,
    "total_eur" numeric(14,2)
);


ALTER TABLE "public"."remesas" OWNER TO "postgres";


COMMENT ON TABLE "public"."remesas" IS 'Lotes de cobro (remesas) por empresa. Reúnen facturas para su gestión conjunta y seguimiento de estado.';



CREATE TABLE IF NOT EXISTS "public"."tarifas" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "empresa_id" "uuid" NOT NULL,
    "energia" "public"."tipo_energia" NOT NULL,
    "acceso" "public"."tarifa_acceso" NOT NULL,
    "oferta" "text",
    "precio_unitario" numeric(12,6),
    "creada_en" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."tarifas" OWNER TO "postgres";


COMMENT ON TABLE "public"."tarifas" IS 'Catálogo de tarifas de cada comercializadora (luz/gas) con su acceso y campo libre "OFERTA".';



CREATE TABLE IF NOT EXISTS "public"."usuarios_app" (
    "user_id" "uuid" NOT NULL,
    "empresa_id" "uuid" NOT NULL,
    "rol" "public"."rol_usuario" NOT NULL,
    "email" "text",
    "activo" boolean DEFAULT true NOT NULL,
    "creado_en" timestamp with time zone DEFAULT "now"(),
    "nombre" "text",
    "apellidos" "text",
    "telefono" "text",
    "forzar_cambio_password" boolean DEFAULT false,
    "avatar_url" "text"
);


ALTER TABLE "public"."usuarios_app" OWNER TO "postgres";


COMMENT ON TABLE "public"."usuarios_app" IS 'Usuarios del CRM con su rol (administrador/comercializadora/comercial/cliente) y empresa a la que pertenecen.';



ALTER TABLE ONLY "public"."chat_history" ALTER COLUMN "id" SET DEFAULT "nextval"('"public"."chat_history_id_seq"'::"regclass");



ALTER TABLE ONLY "public"."consumos" ALTER COLUMN "id" SET DEFAULT "nextval"('"public"."consumos_id_seq"'::"regclass");



ALTER TABLE ONLY "public"."lineas_factura" ALTER COLUMN "id" SET DEFAULT "nextval"('"public"."lineas_factura_id_seq"'::"regclass");



ALTER TABLE ONLY "public"."agenda_eventos"
    ADD CONSTRAINT "agenda_eventos_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."asignaciones_comercial"
    ADD CONSTRAINT "asignaciones_comercial_pkey" PRIMARY KEY ("cliente_id", "comercial_user_id");



ALTER TABLE ONLY "public"."chat_history"
    ADD CONSTRAINT "chat_history_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."clientes"
    ADD CONSTRAINT "clientes_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."comparativas"
    ADD CONSTRAINT "comparativas_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."consumos"
    ADD CONSTRAINT "consumos_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."consumos"
    ADD CONSTRAINT "consumos_punto_id_periodo_inicio_periodo_fin_key" UNIQUE ("punto_id", "periodo_inicio", "periodo_fin");



ALTER TABLE ONLY "public"."contactos_cliente"
    ADD CONSTRAINT "contactos_cliente_pkey" PRIMARY KEY ("cliente_id", "user_id");



ALTER TABLE ONLY "public"."contratos"
    ADD CONSTRAINT "contratos_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."documentos"
    ADD CONSTRAINT "documentos_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."empresas"
    ADD CONSTRAINT "empresas_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."facturas"
    ADD CONSTRAINT "facturas_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."lineas_factura"
    ADD CONSTRAINT "lineas_factura_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."notificaciones"
    ADD CONSTRAINT "notificaciones_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."precios_energia"
    ADD CONSTRAINT "precios_energia_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."precios_energia"
    ADD CONSTRAINT "precios_energia_unico_mes_tarifa_empresa" UNIQUE ("empresa_id", "tarifa", "fecha_mes");



ALTER TABLE ONLY "public"."precios_potencia"
    ADD CONSTRAINT "precios_potencia_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."precios_potencia"
    ADD CONSTRAINT "precios_potencia_unico_año_tarifa_empresa" UNIQUE ("empresa_id", "tarifa", "año");



ALTER TABLE ONLY "public"."puntos_suministro"
    ADD CONSTRAINT "puntos_suministro_cliente_id_cups_key" UNIQUE ("cliente_id", "cups");



ALTER TABLE ONLY "public"."puntos_suministro"
    ADD CONSTRAINT "puntos_suministro_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."remesas"
    ADD CONSTRAINT "remesas_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."tarifas"
    ADD CONSTRAINT "tarifas_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."usuarios_app"
    ADD CONSTRAINT "usuarios_app_pkey" PRIMARY KEY ("user_id");



CREATE INDEX "asignaciones_comercial_comercial_user_id_idx" ON "public"."asignaciones_comercial" USING "btree" ("comercial_user_id");



CREATE INDEX "clientes_cif_idx" ON "public"."clientes" USING "btree" ("cif");



CREATE INDEX "clientes_dni_idx" ON "public"."clientes" USING "btree" ("dni");



CREATE INDEX "clientes_email_facturacion_idx" ON "public"."clientes" USING "btree" ("email_facturacion");



CREATE INDEX "clientes_empresa_id_idx" ON "public"."clientes" USING "btree" ("empresa_id");



CREATE INDEX "clientes_nombre_idx" ON "public"."clientes" USING "btree" ("nombre");



CREATE INDEX "comparativas_cliente_id_solicitada_en_idx" ON "public"."comparativas" USING "btree" ("cliente_id", "solicitada_en");



CREATE INDEX "comparativas_cliente_idx" ON "public"."comparativas" USING "btree" ("cliente_id", "solicitada_en");



CREATE INDEX "comparativas_punto_id_solicitada_en_idx" ON "public"."comparativas" USING "btree" ("punto_id", "solicitada_en");



CREATE INDEX "comparativas_punto_idx" ON "public"."comparativas" USING "btree" ("punto_id", "solicitada_en");



CREATE INDEX "consumos_punto_id_periodo_inicio_idx" ON "public"."consumos" USING "btree" ("punto_id", "periodo_inicio");



CREATE INDEX "contratos_comercializadora_id_idx" ON "public"."contratos" USING "btree" ("comercializadora_id");



CREATE INDEX "contratos_fecha_aviso_idx" ON "public"."contratos" USING "btree" ("fecha_aviso");



CREATE INDEX "contratos_fecha_fin_idx" ON "public"."contratos" USING "btree" ("fecha_fin");



CREATE INDEX "contratos_punto_id_idx" ON "public"."contratos" USING "btree" ("punto_id");



CREATE INDEX "documentos_cliente_idx" ON "public"."documentos" USING "btree" ("cliente_id");



CREATE INDEX "documentos_contrato_idx" ON "public"."documentos" USING "btree" ("contrato_id");



CREATE INDEX "documentos_factura_idx" ON "public"."documentos" USING "btree" ("factura_id");



CREATE INDEX "documentos_tipo_idx" ON "public"."documentos" USING "btree" ("tipo");



CREATE INDEX "empresas_cif_idx" ON "public"."empresas" USING "btree" ("cif");



CREATE INDEX "empresas_nombre_idx" ON "public"."empresas" USING "btree" ("nombre");



CREATE UNIQUE INDEX "facturas_cliente_id_numero_idx" ON "public"."facturas" USING "btree" ("cliente_id", "numero");



CREATE INDEX "facturas_fecha_emision_idx" ON "public"."facturas" USING "btree" ("fecha_emision");



CREATE INDEX "facturas_remesa_idx" ON "public"."facturas" USING "btree" ("remesa_id");



CREATE INDEX "facturas_total_eur_idx" ON "public"."facturas" USING "btree" ("total_eur");



CREATE INDEX "idx_agenda_eventos_empresa_fecha" ON "public"."agenda_eventos" USING "btree" ("empresa_id", "fecha_inicio", "fecha_fin");



CREATE INDEX "idx_contratos_fecha_fin" ON "public"."contratos" USING "btree" ("fecha_fin");



CREATE INDEX "idx_documentos_cliente_visible" ON "public"."documentos" USING "btree" ("cliente_id", "visible_para_cliente") WHERE ("visible_para_cliente" = true);



CREATE INDEX "idx_empresas_is_archived" ON "public"."empresas" USING "btree" ("is_archived");



CREATE INDEX "idx_notificaciones_destinatario_leida" ON "public"."notificaciones" USING "btree" ("user_id_destinatario", "leida");



CREATE INDEX "idx_puntos_suministro_cliente" ON "public"."puntos_suministro" USING "btree" ("cliente_id");



CREATE INDEX "lineas_factura_factura_id_idx" ON "public"."lineas_factura" USING "btree" ("factura_id");



CREATE INDEX "notificaciones_cliente_idx" ON "public"."notificaciones" USING "btree" ("cliente_id");



CREATE INDEX "notificaciones_contrato_idx" ON "public"."notificaciones" USING "btree" ("contrato_id");



CREATE INDEX "notificaciones_empresa_idx" ON "public"."notificaciones" USING "btree" ("empresa_id", "estado");



CREATE INDEX "notificaciones_programada_idx" ON "public"."notificaciones" USING "btree" ("programada_para", "estado");



CREATE INDEX "puntos_suministro_cliente_id_idx" ON "public"."puntos_suministro" USING "btree" ("cliente_id");



CREATE INDEX "puntos_suministro_cups_idx" ON "public"."puntos_suministro" USING "btree" ("cups");



CREATE INDEX "puntos_suministro_direccion_idx" ON "public"."puntos_suministro" USING "btree" ("direccion");



CREATE INDEX "remesas_empresa_idx" ON "public"."remesas" USING "btree" ("empresa_id", "creada_en");



CREATE INDEX "tarifas_empresa_id_idx" ON "public"."tarifas" USING "btree" ("empresa_id");



CREATE INDEX "tarifas_energia_acceso_idx" ON "public"."tarifas" USING "btree" ("energia", "acceso");



CREATE INDEX "usuarios_app_email_idx" ON "public"."usuarios_app" USING "btree" ("email");



CREATE INDEX "usuarios_app_empresa_id_idx" ON "public"."usuarios_app" USING "btree" ("empresa_id");



CREATE INDEX "usuarios_app_rol_idx" ON "public"."usuarios_app" USING "btree" ("rol");



CREATE OR REPLACE TRIGGER "trg_agenda_eventos_set_creator" BEFORE INSERT ON "public"."agenda_eventos" FOR EACH ROW EXECUTE FUNCTION "public"."agenda_eventos_set_creator"();



ALTER TABLE ONLY "public"."agenda_eventos"
    ADD CONSTRAINT "agenda_eventos_empresa_id_fkey" FOREIGN KEY ("empresa_id") REFERENCES "public"."empresas"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."agenda_eventos"
    ADD CONSTRAINT "agenda_eventos_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."usuarios_app"("user_id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."asignaciones_comercial"
    ADD CONSTRAINT "asignaciones_comercial_cliente_id_fkey" FOREIGN KEY ("cliente_id") REFERENCES "public"."clientes"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."asignaciones_comercial"
    ADD CONSTRAINT "asignaciones_comercial_comercial_user_id_fkey" FOREIGN KEY ("comercial_user_id") REFERENCES "public"."usuarios_app"("user_id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."clientes"
    ADD CONSTRAINT "clientes_empresa_id_fkey" FOREIGN KEY ("empresa_id") REFERENCES "public"."empresas"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."comparativas"
    ADD CONSTRAINT "comparativas_cliente_id_fkey" FOREIGN KEY ("cliente_id") REFERENCES "public"."clientes"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."comparativas"
    ADD CONSTRAINT "comparativas_creado_por_user_id_fkey" FOREIGN KEY ("creado_por_user_id") REFERENCES "public"."usuarios_app"("user_id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."comparativas"
    ADD CONSTRAINT "comparativas_punto_id_fkey" FOREIGN KEY ("punto_id") REFERENCES "public"."puntos_suministro"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."consumos"
    ADD CONSTRAINT "consumos_punto_id_fkey" FOREIGN KEY ("punto_id") REFERENCES "public"."puntos_suministro"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."contactos_cliente"
    ADD CONSTRAINT "contactos_cliente_cliente_id_fkey" FOREIGN KEY ("cliente_id") REFERENCES "public"."clientes"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."contactos_cliente"
    ADD CONSTRAINT "contactos_cliente_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."usuarios_app"("user_id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."contratos"
    ADD CONSTRAINT "contratos_comercializadora_id_fkey" FOREIGN KEY ("comercializadora_id") REFERENCES "public"."empresas"("id") ON DELETE RESTRICT;



ALTER TABLE ONLY "public"."contratos"
    ADD CONSTRAINT "contratos_punto_id_fkey" FOREIGN KEY ("punto_id") REFERENCES "public"."puntos_suministro"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."documentos"
    ADD CONSTRAINT "documentos_cliente_id_fkey" FOREIGN KEY ("cliente_id") REFERENCES "public"."clientes"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."documentos"
    ADD CONSTRAINT "documentos_contrato_id_fkey" FOREIGN KEY ("contrato_id") REFERENCES "public"."contratos"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."documentos"
    ADD CONSTRAINT "documentos_factura_id_fkey" FOREIGN KEY ("factura_id") REFERENCES "public"."facturas"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."documentos"
    ADD CONSTRAINT "documentos_punto_id_fkey" FOREIGN KEY ("punto_id") REFERENCES "public"."puntos_suministro"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."documentos"
    ADD CONSTRAINT "documentos_subido_por_user_id_fkey" FOREIGN KEY ("subido_por_user_id") REFERENCES "public"."usuarios_app"("user_id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."facturas"
    ADD CONSTRAINT "facturas_cliente_id_fkey" FOREIGN KEY ("cliente_id") REFERENCES "public"."clientes"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."facturas"
    ADD CONSTRAINT "facturas_remesa_id_fkey" FOREIGN KEY ("remesa_id") REFERENCES "public"."remesas"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."lineas_factura"
    ADD CONSTRAINT "lineas_factura_factura_id_fkey" FOREIGN KEY ("factura_id") REFERENCES "public"."facturas"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."notificaciones"
    ADD CONSTRAINT "notificaciones_agenda_evento_id_fkey" FOREIGN KEY ("agenda_evento_id") REFERENCES "public"."agenda_eventos"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."notificaciones"
    ADD CONSTRAINT "notificaciones_cliente_id_fkey" FOREIGN KEY ("cliente_id") REFERENCES "public"."clientes"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."notificaciones"
    ADD CONSTRAINT "notificaciones_contrato_id_fkey" FOREIGN KEY ("contrato_id") REFERENCES "public"."contratos"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."notificaciones"
    ADD CONSTRAINT "notificaciones_creada_por_user_id_fkey" FOREIGN KEY ("creada_por_user_id") REFERENCES "public"."usuarios_app"("user_id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."notificaciones"
    ADD CONSTRAINT "notificaciones_empresa_id_fkey" FOREIGN KEY ("empresa_id") REFERENCES "public"."empresas"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."notificaciones"
    ADD CONSTRAINT "notificaciones_user_id_destinatario_fkey" FOREIGN KEY ("user_id_destinatario") REFERENCES "public"."usuarios_app"("user_id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."precios_energia"
    ADD CONSTRAINT "precios_energia_empresa_id_fkey" FOREIGN KEY ("empresa_id") REFERENCES "public"."empresas"("id");



ALTER TABLE ONLY "public"."precios_potencia"
    ADD CONSTRAINT "precios_potencia_empresa_id_fkey" FOREIGN KEY ("empresa_id") REFERENCES "public"."empresas"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."puntos_suministro"
    ADD CONSTRAINT "puntos_suministro_cliente_id_fkey" FOREIGN KEY ("cliente_id") REFERENCES "public"."clientes"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."remesas"
    ADD CONSTRAINT "remesas_empresa_id_fkey" FOREIGN KEY ("empresa_id") REFERENCES "public"."empresas"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."tarifas"
    ADD CONSTRAINT "tarifas_empresa_id_fkey" FOREIGN KEY ("empresa_id") REFERENCES "public"."empresas"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."usuarios_app"
    ADD CONSTRAINT "usuarios_app_empresa_id_fkey" FOREIGN KEY ("empresa_id") REFERENCES "public"."empresas"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."usuarios_app"
    ADD CONSTRAINT "usuarios_app_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



CREATE POLICY "Permitir DELETE a administradores en asignaciones_comercial" ON "public"."asignaciones_comercial" FOR DELETE USING ((EXISTS ( SELECT 1
   FROM "public"."usuarios_app" "u"
  WHERE (("u"."user_id" = "auth"."uid"()) AND ("u"."rol" = 'administrador'::"public"."rol_usuario")))));



CREATE POLICY "Permitir DELETE a propietarios o admins" ON "public"."agenda_eventos" FOR DELETE USING (("public"."is_admin"() OR (("public"."current_user_role"() = 'comercial'::"text") AND ("user_id" = "auth"."uid"()))));



CREATE POLICY "Permitir INSERT a administradores" ON "public"."asignaciones_comercial" FOR INSERT WITH CHECK ((EXISTS ( SELECT 1
   FROM "public"."usuarios_app" "u"
  WHERE (("u"."user_id" = "auth"."uid"()) AND ("u"."rol" = 'administrador'::"public"."rol_usuario")))));



CREATE POLICY "Permitir INSERT a usuarios autorizados" ON "public"."agenda_eventos" FOR INSERT WITH CHECK ((("public"."current_user_role"() = ANY (ARRAY['administrador'::"text", 'comercial'::"text"])) AND ("public"."is_admin"() OR ("empresa_id" = "public"."get_my_empresa_id"()))));



CREATE POLICY "Permitir SELECT a administradores en asignaciones_comercial" ON "public"."asignaciones_comercial" FOR SELECT USING ((EXISTS ( SELECT 1
   FROM "public"."usuarios_app" "u"
  WHERE (("u"."user_id" = "auth"."uid"()) AND ("u"."rol" = 'administrador'::"public"."rol_usuario")))));



CREATE POLICY "Permitir SELECT a usuarios autorizados" ON "public"."agenda_eventos" FOR SELECT USING (("public"."is_admin"() OR (("public"."current_user_role"() = 'comercial'::"text") AND ("user_id" = "auth"."uid"()))));



CREATE POLICY "Permitir UPDATE a propietarios o admins" ON "public"."agenda_eventos" FOR UPDATE USING (("public"."is_admin"() OR (("public"."current_user_role"() = 'comercial'::"text") AND ("user_id" = "auth"."uid"())))) WITH CHECK (("public"."is_admin"() OR ("empresa_id" = "public"."get_my_empresa_id"())));



CREATE POLICY "Permitir a clientes ver sus contactos" ON "public"."contactos_cliente" FOR SELECT USING (("user_id" = "auth"."uid"()));



CREATE POLICY "Permitir a comerciales ver sus asignaciones" ON "public"."asignaciones_comercial" FOR SELECT USING (("comercial_user_id" = "auth"."uid"()));



ALTER TABLE "public"."agenda_eventos" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."asignaciones_comercial" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "cli_delete" ON "public"."clientes" FOR DELETE USING ("public"."is_admin"());



CREATE POLICY "cli_insert" ON "public"."clientes" FOR INSERT WITH CHECK (("public"."current_user_role"() = ANY (ARRAY['administrador'::"text", 'comercial'::"text"])));



CREATE POLICY "cli_select" ON "public"."clientes" FOR SELECT USING ("public"."can_access_cliente"("id"));



CREATE POLICY "cli_update" ON "public"."clientes" FOR UPDATE USING (("public"."current_user_role"() = ANY (ARRAY['administrador'::"text", 'comercial'::"text"])));



ALTER TABLE "public"."clientes" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "cmp_delete" ON "public"."comparativas" FOR DELETE USING ("public"."is_admin"());



CREATE POLICY "cmp_insert" ON "public"."comparativas" FOR INSERT WITH CHECK (("public"."current_user_role"() = ANY (ARRAY['administrador'::"text", 'comercial'::"text"])));



CREATE POLICY "cmp_select" ON "public"."comparativas" FOR SELECT USING (("public"."is_admin"() OR ("public"."current_user_role"() = 'comercial'::"text")));



CREATE POLICY "cmp_update" ON "public"."comparativas" FOR UPDATE USING ("public"."is_admin"());



CREATE POLICY "co_select" ON "public"."contratos" FOR SELECT USING ("public"."can_access_contrato"("id"));



ALTER TABLE "public"."comparativas" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "con_delete" ON "public"."contratos" FOR DELETE USING (("public"."is_admin"() AND "public"."can_access_cliente"(( SELECT "ps"."cliente_id"
   FROM "public"."puntos_suministro" "ps"
  WHERE ("ps"."id" = "contratos"."punto_id")))));



CREATE POLICY "con_insert" ON "public"."contratos" FOR INSERT WITH CHECK (("public"."can_access_cliente"(( SELECT "ps"."cliente_id"
   FROM "public"."puntos_suministro" "ps"
  WHERE ("ps"."id" = "contratos"."punto_id"))) AND ("public"."current_user_role"() = ANY (ARRAY['administrador'::"text", 'comercial'::"text"]))));



CREATE POLICY "con_select" ON "public"."contratos" FOR SELECT USING ("public"."can_access_cliente"(( SELECT "ps"."cliente_id"
   FROM "public"."puntos_suministro" "ps"
  WHERE ("ps"."id" = "contratos"."punto_id"))));



CREATE POLICY "con_update" ON "public"."contratos" FOR UPDATE USING (("public"."can_access_cliente"(( SELECT "ps"."cliente_id"
   FROM "public"."puntos_suministro" "ps"
  WHERE ("ps"."id" = "contratos"."punto_id"))) AND ("public"."current_user_role"() = ANY (ARRAY['administrador'::"text", 'comercial'::"text"]))));



ALTER TABLE "public"."consumos" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."contactos_cliente" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."contratos" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "cs_cud_admin" ON "public"."consumos" USING ("public"."is_admin"()) WITH CHECK ("public"."is_admin"());



CREATE POLICY "cs_select" ON "public"."consumos" FOR SELECT USING ("public"."can_access_punto"("punto_id"));



CREATE POLICY "doc_delete" ON "public"."documentos" FOR DELETE USING (("public"."is_admin"() AND "public"."can_access_cliente"("cliente_id")));



CREATE POLICY "doc_insert" ON "public"."documentos" FOR INSERT WITH CHECK (("public"."can_access_cliente"("cliente_id") AND ("public"."current_user_role"() = ANY (ARRAY['administrador'::"text", 'comercial'::"text"]))));



CREATE POLICY "doc_select" ON "public"."documentos" FOR SELECT USING ("public"."can_access_cliente"("cliente_id"));



CREATE POLICY "doc_update" ON "public"."documentos" FOR UPDATE USING (("public"."can_access_cliente"("cliente_id") AND ("public"."current_user_role"() = ANY (ARRAY['administrador'::"text", 'comercial'::"text"]))));



ALTER TABLE "public"."documentos" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "emp_all_admin" ON "public"."empresas" USING ("public"."is_admin"()) WITH CHECK ("public"."is_admin"());



CREATE POLICY "emp_select" ON "public"."empresas" FOR SELECT USING (true);



ALTER TABLE "public"."empresas" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "fa_cud_admin" ON "public"."facturas" USING ("public"."is_admin"()) WITH CHECK ("public"."is_admin"());



CREATE POLICY "fa_select" ON "public"."facturas" FOR SELECT USING ("public"."can_access_factura"("id"));



ALTER TABLE "public"."facturas" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "lifa_cud_admin" ON "public"."lineas_factura" USING ("public"."is_admin"()) WITH CHECK ("public"."is_admin"());



CREATE POLICY "lifa_select" ON "public"."lineas_factura" FOR SELECT USING ((EXISTS ( SELECT 1
   FROM "public"."facturas" "f"
  WHERE (("f"."id" = "lineas_factura"."factura_id") AND "public"."can_access_factura"("f"."id")))));



ALTER TABLE "public"."lineas_factura" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "noti_all_admin" ON "public"."notificaciones" USING ("public"."is_admin"()) WITH CHECK ("public"."is_admin"());



ALTER TABLE "public"."notificaciones" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "ps_delete" ON "public"."puntos_suministro" FOR DELETE USING (("public"."is_admin"() AND "public"."can_access_cliente"("cliente_id")));



CREATE POLICY "ps_insert" ON "public"."puntos_suministro" FOR INSERT WITH CHECK (("public"."can_access_cliente"("cliente_id") AND ("public"."current_user_role"() = ANY (ARRAY['administrador'::"text", 'comercial'::"text"]))));



CREATE POLICY "ps_select" ON "public"."puntos_suministro" FOR SELECT USING ("public"."can_access_cliente"("cliente_id"));



CREATE POLICY "ps_update" ON "public"."puntos_suministro" FOR UPDATE USING (("public"."can_access_cliente"("cliente_id") AND ("public"."current_user_role"() = ANY (ARRAY['administrador'::"text", 'comercial'::"text"]))));



ALTER TABLE "public"."puntos_suministro" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "re_all_admin" ON "public"."remesas" USING ("public"."is_admin"()) WITH CHECK ("public"."is_admin"());



ALTER TABLE "public"."remesas" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "tar_cud_admin" ON "public"."tarifas" USING ("public"."is_admin"()) WITH CHECK ("public"."is_admin"());



CREATE POLICY "tar_select_admin" ON "public"."tarifas" FOR SELECT USING ("public"."is_admin"());



ALTER TABLE "public"."tarifas" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "ua_delete" ON "public"."usuarios_app" FOR DELETE USING ("public"."is_admin"());



CREATE POLICY "ua_insert" ON "public"."usuarios_app" FOR INSERT WITH CHECK ("public"."is_admin"());



CREATE POLICY "ua_select" ON "public"."usuarios_app" FOR SELECT USING (("public"."is_admin"() OR ("user_id" = "auth"."uid"())));



CREATE POLICY "ua_update" ON "public"."usuarios_app" FOR UPDATE USING (("public"."is_admin"() OR ("user_id" = "auth"."uid"())));



ALTER TABLE "public"."usuarios_app" ENABLE ROW LEVEL SECURITY;




ALTER PUBLICATION "supabase_realtime" OWNER TO "postgres";












GRANT USAGE ON SCHEMA "public" TO "postgres";
GRANT USAGE ON SCHEMA "public" TO "anon";
GRANT USAGE ON SCHEMA "public" TO "authenticated";
GRANT USAGE ON SCHEMA "public" TO "service_role";














































































































































































GRANT ALL ON FUNCTION "public"."agenda_eventos_set_creator"() TO "anon";
GRANT ALL ON FUNCTION "public"."agenda_eventos_set_creator"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."agenda_eventos_set_creator"() TO "service_role";



GRANT ALL ON FUNCTION "public"."belongs_to_empresa"("eid" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."belongs_to_empresa"("eid" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."belongs_to_empresa"("eid" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."can_access_cliente"("id_cliente" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."can_access_cliente"("id_cliente" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."can_access_cliente"("id_cliente" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."can_access_contrato"("coid" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."can_access_contrato"("coid" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."can_access_contrato"("coid" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."can_access_factura"("fid" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."can_access_factura"("fid" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."can_access_factura"("fid" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."can_access_punto"("pid" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."can_access_punto"("pid" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."can_access_punto"("pid" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."current_user_empresa_id"() TO "anon";
GRANT ALL ON FUNCTION "public"."current_user_empresa_id"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."current_user_empresa_id"() TO "service_role";



GRANT ALL ON FUNCTION "public"."current_user_role"() TO "anon";
GRANT ALL ON FUNCTION "public"."current_user_role"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."current_user_role"() TO "service_role";



GRANT ALL ON FUNCTION "public"."delete_contrato"("contrato_id_to_delete" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."delete_contrato"("contrato_id_to_delete" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."delete_contrato"("contrato_id_to_delete" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."delete_punto_suministro"("punto_id_to_delete" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."delete_punto_suministro"("punto_id_to_delete" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."delete_punto_suministro"("punto_id_to_delete" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_agenda_items"("fecha_query_inicio" timestamp with time zone, "fecha_query_fin" timestamp with time zone) TO "anon";
GRANT ALL ON FUNCTION "public"."get_agenda_items"("fecha_query_inicio" timestamp with time zone, "fecha_query_fin" timestamp with time zone) TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_agenda_items"("fecha_query_inicio" timestamp with time zone, "fecha_query_fin" timestamp with time zone) TO "service_role";



GRANT ALL ON FUNCTION "public"."get_all_root_documents"() TO "anon";
GRANT ALL ON FUNCTION "public"."get_all_root_documents"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_all_root_documents"() TO "service_role";



GRANT ALL ON FUNCTION "public"."get_my_empresa_id"() TO "anon";
GRANT ALL ON FUNCTION "public"."get_my_empresa_id"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_my_empresa_id"() TO "service_role";



GRANT ALL ON FUNCTION "public"."is_admin"() TO "anon";
GRANT ALL ON FUNCTION "public"."is_admin"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."is_admin"() TO "service_role";



GRANT ALL ON FUNCTION "public"."is_valid_uuid"("uuid_text" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."is_valid_uuid"("uuid_text" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."is_valid_uuid"("uuid_text" "text") TO "service_role";



GRANT ALL ON TABLE "public"."clientes" TO "anon";
GRANT ALL ON TABLE "public"."clientes" TO "authenticated";
GRANT ALL ON TABLE "public"."clientes" TO "service_role";



GRANT ALL ON FUNCTION "public"."search_clientes"("search_text" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."search_clientes"("search_text" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."search_clientes"("search_text" "text") TO "service_role";



GRANT ALL ON TABLE "public"."contratos" TO "anon";
GRANT ALL ON TABLE "public"."contratos" TO "authenticated";
GRANT ALL ON TABLE "public"."contratos" TO "service_role";



GRANT ALL ON FUNCTION "public"."search_contratos"("search_text" "text", "p_cliente_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."search_contratos"("search_text" "text", "p_cliente_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."search_contratos"("search_text" "text", "p_cliente_id" "uuid") TO "service_role";



GRANT ALL ON TABLE "public"."puntos_suministro" TO "anon";
GRANT ALL ON TABLE "public"."puntos_suministro" TO "authenticated";
GRANT ALL ON TABLE "public"."puntos_suministro" TO "service_role";



GRANT ALL ON FUNCTION "public"."search_puntos_suministro"("search_text" "text", "p_cliente_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."search_puntos_suministro"("search_text" "text", "p_cliente_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."search_puntos_suministro"("search_text" "text", "p_cliente_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."set_folder_visibility"("p_cliente_id" "uuid", "p_folder_path" "text", "p_is_visible" boolean) TO "anon";
GRANT ALL ON FUNCTION "public"."set_folder_visibility"("p_cliente_id" "uuid", "p_folder_path" "text", "p_is_visible" boolean) TO "authenticated";
GRANT ALL ON FUNCTION "public"."set_folder_visibility"("p_cliente_id" "uuid", "p_folder_path" "text", "p_is_visible" boolean) TO "service_role";



GRANT ALL ON FUNCTION "public"."unaccent"("text") TO "postgres";
GRANT ALL ON FUNCTION "public"."unaccent"("text") TO "anon";
GRANT ALL ON FUNCTION "public"."unaccent"("text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."unaccent"("text") TO "service_role";



GRANT ALL ON FUNCTION "public"."unaccent"("regdictionary", "text") TO "postgres";
GRANT ALL ON FUNCTION "public"."unaccent"("regdictionary", "text") TO "anon";
GRANT ALL ON FUNCTION "public"."unaccent"("regdictionary", "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."unaccent"("regdictionary", "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."unaccent_init"("internal") TO "postgres";
GRANT ALL ON FUNCTION "public"."unaccent_init"("internal") TO "anon";
GRANT ALL ON FUNCTION "public"."unaccent_init"("internal") TO "authenticated";
GRANT ALL ON FUNCTION "public"."unaccent_init"("internal") TO "service_role";



GRANT ALL ON FUNCTION "public"."unaccent_lexize"("internal", "internal", "internal", "internal") TO "postgres";
GRANT ALL ON FUNCTION "public"."unaccent_lexize"("internal", "internal", "internal", "internal") TO "anon";
GRANT ALL ON FUNCTION "public"."unaccent_lexize"("internal", "internal", "internal", "internal") TO "authenticated";
GRANT ALL ON FUNCTION "public"."unaccent_lexize"("internal", "internal", "internal", "internal") TO "service_role";
























GRANT ALL ON TABLE "public"."agenda_eventos" TO "anon";
GRANT ALL ON TABLE "public"."agenda_eventos" TO "authenticated";
GRANT ALL ON TABLE "public"."agenda_eventos" TO "service_role";



GRANT ALL ON TABLE "public"."asignaciones_comercial" TO "anon";
GRANT ALL ON TABLE "public"."asignaciones_comercial" TO "authenticated";
GRANT ALL ON TABLE "public"."asignaciones_comercial" TO "service_role";



GRANT ALL ON TABLE "public"."chat_history" TO "anon";
GRANT ALL ON TABLE "public"."chat_history" TO "authenticated";
GRANT ALL ON TABLE "public"."chat_history" TO "service_role";



GRANT ALL ON SEQUENCE "public"."chat_history_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."chat_history_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."chat_history_id_seq" TO "service_role";



GRANT ALL ON TABLE "public"."comparativas" TO "anon";
GRANT ALL ON TABLE "public"."comparativas" TO "authenticated";
GRANT ALL ON TABLE "public"."comparativas" TO "service_role";



GRANT ALL ON TABLE "public"."consumos" TO "anon";
GRANT ALL ON TABLE "public"."consumos" TO "authenticated";
GRANT ALL ON TABLE "public"."consumos" TO "service_role";



GRANT ALL ON SEQUENCE "public"."consumos_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."consumos_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."consumos_id_seq" TO "service_role";



GRANT ALL ON TABLE "public"."contactos_cliente" TO "anon";
GRANT ALL ON TABLE "public"."contactos_cliente" TO "authenticated";
GRANT ALL ON TABLE "public"."contactos_cliente" TO "service_role";



GRANT ALL ON TABLE "public"."documentos" TO "anon";
GRANT ALL ON TABLE "public"."documentos" TO "authenticated";
GRANT ALL ON TABLE "public"."documentos" TO "service_role";



GRANT ALL ON TABLE "public"."empresas" TO "anon";
GRANT ALL ON TABLE "public"."empresas" TO "authenticated";
GRANT ALL ON TABLE "public"."empresas" TO "service_role";



GRANT ALL ON TABLE "public"."facturas" TO "anon";
GRANT ALL ON TABLE "public"."facturas" TO "authenticated";
GRANT ALL ON TABLE "public"."facturas" TO "service_role";



GRANT ALL ON TABLE "public"."lineas_factura" TO "anon";
GRANT ALL ON TABLE "public"."lineas_factura" TO "authenticated";
GRANT ALL ON TABLE "public"."lineas_factura" TO "service_role";



GRANT ALL ON SEQUENCE "public"."lineas_factura_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."lineas_factura_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."lineas_factura_id_seq" TO "service_role";



GRANT ALL ON TABLE "public"."notificaciones" TO "anon";
GRANT ALL ON TABLE "public"."notificaciones" TO "authenticated";
GRANT ALL ON TABLE "public"."notificaciones" TO "service_role";



GRANT ALL ON TABLE "public"."precios_energia" TO "anon";
GRANT ALL ON TABLE "public"."precios_energia" TO "authenticated";
GRANT ALL ON TABLE "public"."precios_energia" TO "service_role";



GRANT ALL ON TABLE "public"."precios_potencia" TO "anon";
GRANT ALL ON TABLE "public"."precios_potencia" TO "authenticated";
GRANT ALL ON TABLE "public"."precios_potencia" TO "service_role";



GRANT ALL ON TABLE "public"."remesas" TO "anon";
GRANT ALL ON TABLE "public"."remesas" TO "authenticated";
GRANT ALL ON TABLE "public"."remesas" TO "service_role";



GRANT ALL ON TABLE "public"."tarifas" TO "anon";
GRANT ALL ON TABLE "public"."tarifas" TO "authenticated";
GRANT ALL ON TABLE "public"."tarifas" TO "service_role";



GRANT ALL ON TABLE "public"."usuarios_app" TO "anon";
GRANT ALL ON TABLE "public"."usuarios_app" TO "authenticated";
GRANT ALL ON TABLE "public"."usuarios_app" TO "service_role";









ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "service_role";






ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "service_role";






ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "service_role";
































  create policy "Permitir a usuarios subir su propio avatar 1oj01fe_0"
  on "storage"."objects"
  as permissive
  for insert
  to authenticated
with check (((bucket_id = 'avatars'::text) AND (auth.uid() = ((storage.foldername(name))[1])::uuid)));



  create policy "Permitir a usuarios subir su propio avatar 1oj01fe_1"
  on "storage"."objects"
  as permissive
  for update
  to authenticated
using (((bucket_id = 'avatars'::text) AND (auth.uid() = ((storage.foldername(name))[1])::uuid)));



  create policy "Permitir borrado a usuarios autorizados"
  on "storage"."objects"
  as permissive
  for delete
  to public
using (((bucket_id = 'documentos'::text) AND public.is_valid_uuid(path_tokens[2]) AND public.can_access_cliente((path_tokens[2])::uuid) AND (public.current_user_role() <> 'cliente'::text)));



  create policy "Permitir descarga a usuarios autorizados"
  on "storage"."objects"
  as permissive
  for select
  to public
using (((bucket_id = 'documentos'::text) AND public.is_valid_uuid(path_tokens[2]) AND public.can_access_cliente((path_tokens[2])::uuid)));



  create policy "Permitir lectura pública de avatares 1oj01fe_0"
  on "storage"."objects"
  as permissive
  for select
  to anon, authenticated
using ((bucket_id = 'avatars'::text));



  create policy "Permitir subida a roles autorizados"
  on "storage"."objects"
  as permissive
  for insert
  to authenticated
with check (((bucket_id = 'documentos'::text) AND (public.current_user_role() = ANY (ARRAY['administrador'::text, 'comercial'::text])) AND public.can_access_cliente((path_tokens[2])::uuid)));



  create policy "Permitir subida a usuarios autorizados"
  on "storage"."objects"
  as permissive
  for insert
  to public
with check (((bucket_id = 'documentos'::text) AND public.is_valid_uuid(path_tokens[2]) AND public.can_access_cliente((path_tokens[2])::uuid) AND (public.current_user_role() <> 'cliente'::text)));



  create policy "logos_empresas delete (admin)"
  on "storage"."objects"
  as permissive
  for delete
  to authenticated
using (((bucket_id = 'logos_empresas'::text) AND (EXISTS ( SELECT 1
   FROM public.usuarios_app ua
  WHERE ((ua.user_id = auth.uid()) AND (ua.rol = 'administrador'::public.rol_usuario))))));



  create policy "logos_empresas insert (admin)"
  on "storage"."objects"
  as permissive
  for insert
  to authenticated
with check (((bucket_id = 'logos_empresas'::text) AND (EXISTS ( SELECT 1
   FROM public.usuarios_app ua
  WHERE ((ua.user_id = auth.uid()) AND (ua.rol = 'administrador'::public.rol_usuario))))));



  create policy "logos_empresas select (authed)"
  on "storage"."objects"
  as permissive
  for select
  to authenticated
using ((bucket_id = 'logos_empresas'::text));



  create policy "logos_empresas update (admin)"
  on "storage"."objects"
  as permissive
  for update
  to authenticated
using (((bucket_id = 'logos_empresas'::text) AND (EXISTS ( SELECT 1
   FROM public.usuarios_app ua
  WHERE ((ua.user_id = auth.uid()) AND (ua.rol = 'administrador'::public.rol_usuario))))))
with check (((bucket_id = 'logos_empresas'::text) AND (EXISTS ( SELECT 1
   FROM public.usuarios_app ua
  WHERE ((ua.user_id = auth.uid()) AND (ua.rol = 'administrador'::public.rol_usuario))))));



