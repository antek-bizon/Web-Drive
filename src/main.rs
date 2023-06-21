use std::env;

use actix_web::{web, App, HttpServer};
use dotenv::dotenv;
use env_logger::Builder;
use sqlx::{mysql::MySqlPoolOptions, MySql, Pool};

use controller::{confirm_user, login_user, ping, register_user};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    Builder::new().parse_env("APP_LOG_LEVEL").init();

    let server_ip = env::var("SERVER_IP").expect("SERVER_IP must be set");
    let port = env::var("PORT")
        .expect("PORT must be set")
        .parse::<u16>()
        .expect("PORT must be a u16");
    let secret_key = std::env::var("SECRET_KEY").expect("SECRET_KEY must be set.");
    log::trace!("Secret key: {}", secret_key);

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = MySqlPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Error building a connection pool");

    log::info!("Starting server {} on port {}", server_ip, port);
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(AppState {
                db: pool.clone(),
                secret_key: secret_key.clone(),
            }))
            .service(
                web::scope("/api")
                    .service(ping)
                    .service(register_user)
                    .service(confirm_user)
                    .service(login_user),
            )
    })
    .workers(1)
    .bind((server_ip, port))?
    .run()
    .await
}

pub struct AppState {
    db: Pool<MySql>,
    secret_key: String,
}

mod controller {
    use crate::AppState;
    use actix_web::{
        get,
        http::header::ContentType,
        post,
        web::{Data, Json},
        HttpResponse, Responder,
    };
    use jsonwebtoken::{decode, encode, EncodingKey, Header};
    use rand::Rng;
    use serde::{Deserialize, Serialize};
    use sqlx::FromRow;

    #[derive(Deserialize, Debug)]
    pub struct CreateUserBody {
        pub email: String,
        pub nick: String,
        pub password: String,
    }

    #[derive(Deserialize, Debug)]
    pub struct ConfirmUserBody {
        pub email: String,
        pub code: u32,
    }

    #[derive(Deserialize, Debug)]
    pub struct LoginUserBody {
        pub email: String,
        pub password: String,
    }
    #[derive(Serialize, FromRow)]
    struct UserWithToken {
        email: String,
        nick: String,
        token: String,
    }

    #[get("/ping")]
    pub async fn ping() -> impl Responder {
        log::info!("Successfully pinged");
        HttpResponse::Ok().body("Successfully pinged!")
    }

    #[post("/user/register")]
    pub async fn register_user(
        body: Json<CreateUserBody>,
        state: Data<AppState>,
    ) -> impl Responder {
        log::trace!("{:#?}", body);

        let exists = sqlx::query!("SELECT id from users WHERE email = ?", &body.email)
            .fetch_one(&state.db)
            .await;

        if let Err(sqlx::Error::RowNotFound) = exists {
            let mut rng = rand::thread_rng();
            let code = rng.gen_range(100_000..999_999);
            let result = sqlx::query!(
                "INSERT INTO users(email, nick, password, confirmed) VALUES (?, ?, SHA2(?, 256), ?)",
                &body.email,
                &body.nick,
                &body.password,
                &code
            )
            .execute(&state.db)
            .await;

            if result.is_err() {
                return HttpResponse::InternalServerError().body("Failed to create a user");
            }
            log::trace!("{:?}", result);
            HttpResponse::Ok().body(format!("Successfully added user: code {}", code))
        } else if exists.is_ok() {
            HttpResponse::Conflict().body("User with given email already exists")
        } else {
            HttpResponse::InternalServerError().body("Something went wrong during adding user")
        }
    }

    #[post("/user/confirm")]
    pub async fn confirm_user(
        body: Json<ConfirmUserBody>,
        state: Data<AppState>,
    ) -> impl Responder {
        log::trace!("{:?}", body);

        let check_user = sqlx::query!(
            "SELECT id, email, confirmed from users WHERE email = ?",
            &body.email
        )
        .fetch_one(&state.db)
        .await;

        match check_user {
            Ok(user) => {
                if user.confirmed == 0 {
                    return HttpResponse::AlreadyReported().body("User has already been confirmed");
                }

                if user.confirmed == body.code {
                    let update_user =
                        sqlx::query!("UPDATE users SET confirmed = 0 WHERE users.id = ?", user.id)
                            .execute(&state.db)
                            .await;

                    if let Ok(updated_user) = update_user {
                        if updated_user.rows_affected() > 0 {
                            return HttpResponse::Ok().body("User successfully confirmed");
                        }
                    }

                    return HttpResponse::InternalServerError()
                        .body("Something went wrong during updating user's confimation");
                }

                HttpResponse::BadRequest().body("Wrong code")
            }
            Err(error) => match error {
                sqlx::Error::RowNotFound => HttpResponse::NotFound().body("User not found"),
                _ => HttpResponse::InternalServerError()
                    .body("Something went wrong during confirming user"),
            },
        }
    }

    #[post("/user/login")]
    pub async fn login_user(body: Json<LoginUserBody>, state: Data<AppState>) -> impl Responder {
        log::trace!("{:?}", body);

        let check_user = sqlx::query!(
            "SELECT email, nick, confirmed FROM users WHERE email = ? AND password = SHA2(?, 256)",
            &body.email,
            &body.password
        )
        .fetch_one(&state.db)
        .await;

        match check_user {
            Ok(user) => {
                if user.confirmed != 0 {
                    return HttpResponse::Forbidden().body("User hasn't been confirmed yet");
                }

                let encode_token = encode(
                    &Header::default(),
                    &user.email,
                    &EncodingKey::from_secret(state.secret_key.as_bytes()),
                );
                if let Ok(token) = encode_token {
                    log::info!("{:?}", token);

                    let data = UserWithToken {
                        email: user.email,
                        nick: user.nick,
                        token,
                    };
                    return HttpResponse::Ok()
                        .content_type(ContentType::json())
                        .json(data);
                }

                HttpResponse::InternalServerError().body("Failed to create token")
            }
            Err(_) => HttpResponse::Unauthorized().body("Email or password is incorrect"),
        }
    }
}
