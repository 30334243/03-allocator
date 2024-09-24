@echo off
REM Запуск docker-compose
docker-compose up --build

REM Ожидание завершения работы контейнеров
for /f %%i in ('docker-compose ps -q') do (
    docker wait %%i
)

REM Удаление контейнеров
docker-compose down --remove-orphans