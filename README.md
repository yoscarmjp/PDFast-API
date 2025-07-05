# PDFast-API

A very fast, secure and easy to configure API for delivering any file that can be render through HTTP (Videos, Gifs, Vectors, PDF, Images, etc)
This API focus on the performance and its scalable.

# 1. Starting

## 1.0 Requirements

For this application you will just need `docker-compose` since everything will be inside 2 containers, only 1 port needs to be exposed.
The default port used for Crow is `8003`
Can be changed in `Dockerfile`, `docker-compose.yml`, `main.cpp`

## 1.1 Setting up the application
You will need to create an `.env` file in the root directory with the following variables:

- `CORS_ORIGIN` => `STRING` (Full URL of permitted website)
- `ALLOWED_HOSTS` => `STRING` (Sub + Domain of host)
- `ENCRYPTION_ROUNDS` => `INT`
- `ENCRYPTION_KEY` => `STRING` (Salt for encryption)
- `REDIS_URL` => `STRING` (tcp://redis:6379 default)
- `CROW_PORT` => `INT` (8003 default)
- `CROW_HOST` => `STRING` (0.0.0.0 default)

Keep in mind that the default redis URL is
`tcp://redis:6379`

Once you finish setting up the environment you can directly start the application with `sudo docker-compose up --build`

#  2. Usage

## 2.0 Available endpoints
The current deployed endpoints are

- `GET` | `/token` -> Returns a CSRF token and a Session_id that expires in  `60` seconds.
- `GET` | `/PDF/string/string/int` -> Returns the PDF matching its path with the name as `int.pdf` (1.pdf, 2.pdf, ...)
- `POST` | `/PDF/string/string/int` -> Creates or change a PDF in that path (If the directory does not exist, it makes a new one) but it will need the `csrf_token` and `session_id` tokens as provided from `GET` | `/token`

## 2.1 Changing code for endpoints
Everything can be changed from the directory `/src/cpp/controller.cpp`

# 3. Code

## 3.0 Setting up
The setting up has 4 parts including the already mentioned `.env`
It uses a `docker-compose.yml` that creates 2 containers: 1 for Redis for caching the token, and 1 for Crow (The backend server itself)
At the other hand we have the `Dockerfile` that does several things:

1) Dependency installation
		- `cmake`
		- `git`
		- `libboost-all-dev`
		- `libasio-dev`
		- `libhiredis-dev`
2) Redis++
		- `redis-plus-plus` from swenew
3) CrowCpp
		- `Crow`from CrowCpp

It will compile the project and give all the permissions necessary and it will expose port `8003` unless changed.

## 3.1 Flow of information
This API was meant for being used with another API that handles the information in between, so this is more of a Database container.

The files are saved in raw files, since the idea  is to be accessed quickly, the only problem is that only with permission you should be able to modify this.

In order to get the permission you need to be the correct `HOST` and ask for a `session_id` and `csrf_token` that expires in 60 seconds.

The idea behind is that this other API will handle other security layers about the users making the changes.


# 4. License

## 4.0 Free of use
You can do whatever you want with this code and sell it, but I will ask for my name to be included somewhere as a reference to this project.