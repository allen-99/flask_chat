# Чат-блог на Flask с mysqlite
Простой чат-блог с регистраицей и авторизацией, в котором вы можете писать что вашей душе угодно.

# Перед запуском необходимо:
## Выполинть команды
```
python3
from app import db
db.create_all()
exit()
```
## Установить зависимости из `requirements.txt`
```
pip install -r requirements.txt
```
## Создать файл `config.py` в папке `chat`. Пример файла:
```
SQLALCHEMY_DATABASE_URI = "SQLITE:///chat.db"
SECRET_KEY = 'SECRET_KEY'

```

# Запуск из корневой папки
```
python app.py
```
