# ms-security

Proyecto demo con Spring Boot y Spring Security para gestionar la autenticación y autorización con JWT.

## 🚀 Instalación y Ejecución

Sigue estos pasos para configurar y ejecutar el proyecto en tu entorno local.

### Prerrequisitos

Asegúrate de tener instalado lo siguiente:
-   **Java JDK 17** o superior.
-   **Maven** 3.6 o superior.
-   **PostgreSQL** como sistema de gestión de bases de datos.

### 1. Clonar el repositorio

```bash
git clone https://github.com/darttecno/ms-security.git
cd ms-security
```

### 2. Configurar la base de datos

El proyecto utiliza PostgreSQL. Deberás crear una base de datos y luego configurar la conexión en el archivo `application.properties`.

1.  Crea una base de datos en PostgreSQL. Por ejemplo, `ms_security_db`.
2.  Crea el archivo `src/main/resources/application.properties` y añade la siguiente configuración, reemplazando los valores de `url`, `username` y `password` con los de tu base de datos:

    ```properties
    # PostgreSQL
    spring.datasource.url=jdbc:postgresql://localhost:5432/ms_security_db
    spring.datasource.username=tu_usuario
    spring.datasource.password=tu_contraseña
    spring.datasource.driver-class-name=org.postgresql.Driver

    # JPA / Hibernate
    spring.jpa.hibernate.ddl-auto=validate
    spring.jpa.show-sql=true
    spring.jpa.properties.hibernate.format_sql=true
    spring.jpa.properties.hibernate.default_schema=public

    # Liquibase
    spring.liquibase.change-log=classpath:db/changelog/db.changelog-master.yaml
    ```

### 3. Ejecutar la aplicación

Una vez configurada la base de datos, puedes ejecutar la aplicación usando Maven. Las migraciones de la base de datos con Liquibase se aplicarán automáticamente al iniciar la aplicación.

```bash
mvn spring-boot:run
```

La aplicación se iniciará y estará disponible en `http://localhost:8080`.

## 🧪 Probar la API

El proyecto incluye una colección de Postman (`postman_collection.json`) con ejemplos de las solicitudes a los endpoints de la API. Puedes importarla en Postman para probar fácilmente el registro, la autenticación y las demás funcionalidades.
