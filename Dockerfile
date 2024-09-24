# Используем локальный подготовленный образ Ubuntu 22.04
FROM ubuntu-22.04-step-1:1.0

COPY . /app

# Устанавливаем рабочую директорию
WORKDIR /app

RUN cd /app && cmake --workflow --preset wsl-ci

# Копируем deb-пакет на хост-машину
CMD ["sh", "-c","cd .. && cp ./build/install/*.deb /host/"]
