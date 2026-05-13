# Используем легкий официальный образ Python
FROM python:3.11-slim

# Метаданные
LABEL maintainer="your@email.com"
LABEL description="Whatsminer Manager - мониторинг и управление майнерами"

# Рабочая директория
WORKDIR /app

# Копируем зависимости и устанавливаем их
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем приложение
COPY . .

# Создаём непривилегированного пользователя для безопасности
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Порт приложения
EXPOSE 5000

# Переменные окружения по умолчанию (можно переопределить при запуске)
ENV FLASK_APP=app.py \
    FLASK_ENV=production \
    ADMIN_USER=admin \
    SECRET_KEY=change-me-in-production

# Запуск через Gunicorn (продакшен-сервер)
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--threads", "2", "--timeout", "30", "app:app"]
