// ====================================
// НАСТРОЙКИ И ИМПОРТЫ
// ====================================
require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'default-secret-key-change-this';
const ADMIN_PASSWORD = 'Y@vD3lE_Admin#9427';

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const db = new sqlite3.Database('./yavdele.db', (err) => {
    if (err) console.error('❌ Ошибка подключения к БД:', err);
    else { console.log('✅ Подключено к базе данных SQLite'); initDatabase(); }
});

function initDatabase() {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        type TEXT NOT NULL CHECK(type IN ('worker', 'employer')),
        balance INTEGER DEFAULT 0,
        rating REAL DEFAULT 5.0,
        total_ratings INTEGER DEFAULT 0,
        rating_sum INTEGER DEFAULT 0,
        has_premium BOOLEAN DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        location TEXT,
        payment INTEGER NOT NULL,
        difficulty INTEGER NOT NULL CHECK(difficulty BETWEEN 1 AND 5),
        description TEXT NOT NULL,
        requirements TEXT,
        contacts TEXT,
        min_rating REAL DEFAULT 0,
        employer_id INTEGER NOT NULL,
        status TEXT DEFAULT 'open' CHECK(status IN ('open', 'in_progress', 'completed', 'cancelled')),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (employer_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS applications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id INTEGER NOT NULL,
        applicant_id INTEGER NOT NULL,
        employer_id INTEGER NOT NULL,
        status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'accepted', 'work_done', 'completed', 'rejected')),
        worker_rating INTEGER DEFAULT NULL,
        employer_rating INTEGER DEFAULT NULL,
        worker_rated BOOLEAN DEFAULT 0,
        employer_rated BOOLEAN DEFAULT 0,
        payment_claimed BOOLEAN DEFAULT 0,
        applied_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (task_id) REFERENCES tasks(id),
        FOREIGN KEY (applicant_id) REFERENCES users(id),
        FOREIGN KEY (employer_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS chat_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id INTEGER NOT NULL,
        sender_id INTEGER NOT NULL,
        text TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (task_id) REFERENCES tasks(id),
        FOREIGN KEY (sender_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS support_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        sender_type TEXT NOT NULL CHECK(sender_type IN ('user', 'admin')),
        text TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )`);

    console.log('✅ Таблицы базы данных инициализированы');
}

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Требуется авторизация' });
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Неверный токен' });
        req.user = user;
        next();
    });
}

// АУТЕНТИФИКАЦИЯ
app.post('/api/register', async (req, res) => {
    const { username, password, type, agreedToTerms } = req.body;
    if (!username || !password || !type) return res.status(400).json({ error: 'Все поля обязательны' });
    if (!agreedToTerms) return res.status(400).json({ error: 'Необходимо согласиться с условиями договора' });
    if (type !== 'worker' && type !== 'employer') return res.status(400).json({ error: 'Неверный тип пользователя' });
    if (username.length < 3) return res.status(400).json({ error: 'Имя пользователя должно быть не менее 3 символов' });
    if (password.length < 6) return res.status(400).json({ error: 'Пароль должен быть не менее 6 символов' });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run('INSERT INTO users (username, password, type) VALUES (?, ?, ?)', [username, hashedPassword, type], function(err) {
            if (err) {
                if (err.message.includes('UNIQUE')) return res.status(400).json({ error: 'Пользователь уже существует' });
                return res.status(500).json({ error: 'Ошибка создания пользователя' });
            }
            const token = jwt.sign({ id: this.lastID, username, type }, JWT_SECRET, { expiresIn: '7d' });
            res.json({ token });
        });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Все поля обязательны' });

    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) return res.status(500).json({ error: 'Ошибка сервера' });
        if (!user) return res.status(400).json({ error: 'Неверное имя пользователя или пароль' });
        
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: 'Неверное имя пользователя или пароль' });

        const token = jwt.sign({ id: user.id, username: user.username, type: user.type }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token });
    });
});

app.get('/api/profile', authenticateToken, (req, res) => {
    db.get('SELECT id, username, type, balance, rating, has_premium FROM users WHERE id = ?', [req.user.id], (err, user) => {
        if (err) return res.status(500).json({ error: 'Ошибка сервера' });
        if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
        res.json(user);
    });
});

// БАЛАНС
app.post('/api/balance/add', authenticateToken, (req, res) => {
    const { amount } = req.body;
    if (!amount || amount <= 0) return res.status(400).json({ error: 'Неверная сумма' });

    db.run('UPDATE users SET balance = balance + ? WHERE id = ?', [amount, req.user.id], function(err) {
        if (err) return res.status(500).json({ error: 'Ошибка сервера' });
        db.get('SELECT balance FROM users WHERE id = ?', [req.user.id], (err, user) => {
            if (err) return res.status(500).json({ error: 'Ошибка сервера' });
            res.json({ balance: user.balance });
        });
    });
});

app.post('/api/balance/withdraw', authenticateToken, (req, res) => {
    db.get('SELECT balance FROM users WHERE id = ?', [req.user.id], (err, user) => {
        if (err) return res.status(500).json({ error: 'Ошибка сервера' });
        if (user.balance < 3000) return res.status(400).json({ error: 'Недостаточно средств. Минимум для вывода: 3000 Я баллов' });

        const amount = Math.floor(user.balance / 10) * 10;
        db.run('UPDATE users SET balance = balance - ? WHERE id = ?', [amount, req.user.id], function(err) {
            if (err) return res.status(500).json({ error: 'Ошибка сервера' });
            res.json({ message: `Успешно выведено ${amount / 10} рублей`, newBalance: user.balance - amount });
        });
    });
});

// БЛАГОТВОРИТЕЛЬНОСТЬ
app.post('/api/charity/donate', authenticateToken, (req, res) => {
    const { amount } = req.body;
    if (amount < 0) return res.status(400).json({ error: 'Неверная сумма' });
    if (amount === 0) return res.json({ message: 'Пожертвование пропущено' });

    db.get('SELECT balance FROM users WHERE id = ?', [req.user.id], (err, user) => {
        if (err) return res.status(500).json({ error: 'Ошибка сервера' });
        if (user.balance < amount) return res.status(400).json({ error: 'Недостаточно средств' });

        db.run('UPDATE users SET balance = balance - ? WHERE id = ?', [amount, req.user.id], function(err) {
            if (err) return res.status(500).json({ error: 'Ошибка сервера' });
            res.json({ message: `Спасибо за пожертвование ${amount} Я баллов!` });
        });
    });
});

// ЗАДАНИЯ
app.post('/api/tasks', authenticateToken, (req, res) => {
    const { title, category, location, payment, difficulty, description, requirements, contacts, minRating } = req.body;
    if (!title || !description || !payment || !difficulty || !category) {
        return res.status(400).json({ error: 'Обязательные поля отсутствуют' });
    }
    if (payment < 1000) return res.status(400).json({ error: 'Минимальная оплата: 1000 Я баллов' });

    db.get('SELECT balance, has_premium FROM users WHERE id = ?', [req.user.id], (err, user) => {
        if (err) return res.status(500).json({ error: 'Ошибка сервера' });
        if (user.balance < payment) return res.status(400).json({ error: 'Недостаточно средств на балансе' });

        db.run('UPDATE users SET balance = balance - ? WHERE id = ?', [payment, req.user.id], function(err) {
            if (err) return res.status(500).json({ error: 'Ошибка сервера' });
            
            db.run(`INSERT INTO tasks (title, category, location, payment, difficulty, description, requirements, contacts, min_rating, employer_id) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [title, category, location || '', payment, difficulty, description, requirements || '', contacts || '', minRating || 0, req.user.id],
                function(err) {
                    if (err) {
                        db.run('UPDATE users SET balance = balance + ? WHERE id = ?', [payment, req.user.id]);
                        return res.status(500).json({ error: 'Ошибка создания задания' });
                    }
                    res.json({ id: this.lastID, message: 'Задание создано' });
                }
            );
        });
    });
});

app.get('/api/tasks', (req, res) => {
    db.all(`SELECT t.*, u.username as employer_name, u.rating as employer_rating 
            FROM tasks t JOIN users u ON t.employer_id = u.id 
            WHERE t.status = 'open' ORDER BY t.created_at DESC`, [], (err, tasks) => {
        if (err) return res.status(500).json({ error: 'Ошибка сервера' });
        res.json(tasks);
    });
});

app.delete('/api/tasks/:taskId', authenticateToken, (req, res) => {
    db.get('SELECT * FROM tasks WHERE id = ? AND employer_id = ?', [req.params.taskId, req.user.id], (err, task) => {
        if (err) return res.status(500).json({ error: 'Ошибка сервера' });
        if (!task) return res.status(404).json({ error: 'Задание не найдено' });
        if (task.status !== 'open') return res.status(400).json({ error: 'Можно удалять только открытые задания' });

        db.run('DELETE FROM tasks WHERE id = ?', [req.params.taskId], (err) => {
            if (err) return res.status(500).json({ error: 'Ошибка сервера' });
            db.run('UPDATE users SET balance = balance + ? WHERE id = ?', [task.payment, req.user.id], (err) => {
                if (err) return res.status(500).json({ error: 'Ошибка возврата средств' });
                res.json({ message: 'Задание удалено' });
            });
        });
    });
});

// ОТКЛИКИ
app.post('/api/tasks/:taskId/apply', authenticateToken, (req, res) => {
    db.get('SELECT * FROM applications WHERE task_id = ? AND applicant_id = ?', [req.params.taskId, req.user.id], (err, existing) => {
        if (err) return res.status(500).json({ error: 'Ошибка сервера' });
        if (existing) return res.status(400).json({ error: 'Вы уже откликнулись' });

        db.get('SELECT employer_id FROM tasks WHERE id = ?', [req.params.taskId], (err, task) => {
            if (err || !task) return res.status(404).json({ error: 'Задание не найдено' });
            
            db.run('INSERT INTO applications (task_id, applicant_id, employer_id) VALUES (?, ?, ?)', 
                [req.params.taskId, req.user.id, task.employer_id], function(err) {
                    if (err) return res.status(500).json({ error: 'Ошибка сервера' });
                    res.json({ message: 'Отклик отправлен' });
                }
            );
        });
    });
});

app.get('/api/applications/my', authenticateToken, (req, res) => {
    db.all(`SELECT a.*, t.title, t.payment, t.description, t.location, t.contacts, u.username as employer_name 
            FROM applications a 
            JOIN tasks t ON a.task_id = t.id 
            JOIN users u ON t.employer_id = u.id 
            WHERE a.applicant_id = ? 
            ORDER BY a.applied_at DESC`, [req.user.id], (err, applications) => {
        if (err) return res.status(500).json({ error: 'Ошибка сервера' });
        res.json(applications);
    });
});

app.post('/api/applications/:applicationId/accept', authenticateToken, (req, res) => {
    db.get('SELECT * FROM applications WHERE id = ?', [req.params.applicationId], (err, app) => {
        if (err || !app) return res.status(404).json({ error: 'Отклик не найден' });
        if (app.employer_id !== req.user.id) return res.status(403).json({ error: 'Нет прав' });

        db.run('UPDATE applications SET status = ? WHERE id = ?', ['accepted', req.params.applicationId], (err) => {
            if (err) return res.status(500).json({ error: 'Ошибка сервера' });
            db.run('UPDATE tasks SET status = ? WHERE id = ?', ['in_progress', app.task_id], (err) => {
                if (err) return res.status(500).json({ error: 'Ошибка сервера' });
                res.json({ message: 'Отклик принят' });
            });
        });
    });
});

app.post('/api/applications/:applicationId/confirm-work', authenticateToken, (req, res) => {
    db.get('SELECT * FROM applications WHERE id = ?', [req.params.applicationId], (err, app) => {
        if (err || !app) return res.status(404).json({ error: 'Отклик не найден' });
        if (app.employer_id !== req.user.id) return res.status(403).json({ error: 'Нет прав' });

        db.run('UPDATE applications SET status = ? WHERE id = ?', ['work_done', req.params.applicationId], (err) => {
            if (err) return res.status(500).json({ error: 'Ошибка сервера' });
            res.json({ message: 'Работа подтверждена' });
        });
    });
});

app.post('/api/applications/:applicationId/rate-worker', authenticateToken, (req, res) => {
    const { rating } = req.body;
    if (!rating || rating < 1 || rating > 5) return res.status(400).json({ error: 'Оценка от 1 до 5' });

    db.get('SELECT * FROM applications WHERE id = ?', [req.params.applicationId], (err, app) => {
        if (err || !app) return res.status(404).json({ error: 'Отклик не найден' });
        if (app.employer_id !== req.user.id) return res.status(403).json({ error: 'Нет прав' });

        db.run('UPDATE users SET rating_sum = rating_sum + ?, total_ratings = total_ratings + 1 WHERE id = ?', 
            [rating, app.applicant_id], (err) => {
                if (err) return res.status(500).json({ error: 'Ошибка сервера' });
                db.run('UPDATE users SET rating = CAST(rating_sum AS REAL) / total_ratings WHERE id = ?', [app.applicant_id], (err) => {
                    if (err) return res.status(500).json({ error: 'Ошибка сервера' });
                    db.run('UPDATE applications SET worker_rating = ?, employer_rated = 1, status = ? WHERE id = ?', 
                        [rating, 'completed', req.params.applicationId], (err) => {
                            if (err) return res.status(500).json({ error: 'Ошибка сервера' });
                            res.json({ message: 'Оценка поставлена' });
                        }
                    );
                });
            }
        );
    });
});

app.post('/api/applications/:applicationId/rate-employer', authenticateToken, (req, res) => {
    const { rating } = req.body;
    if (!rating || rating < 1 || rating > 5) return res.status(400).json({ error: 'Оценка от 1 до 5' });

    db.get('SELECT * FROM applications WHERE id = ?', [req.params.applicationId], (err, app) => {
        if (err || !app) return res.status(404).json({ error: 'Отклик не найден' });
        if (app.applicant_id !== req.user.id) return res.status(403).json({ error: 'Нет прав' });

        db.run('UPDATE users SET rating_sum = rating_sum + ?, total_ratings = total_ratings + 1 WHERE id = ?', 
            [rating, app.employer_id], (err) => {
                if (err) return res.status(500).json({ error: 'Ошибка сервера' });
                db.run('UPDATE users SET rating = CAST(rating_sum AS REAL) / total_ratings WHERE id = ?', [app.employer_id], (err) => {
                    if (err) return res.status(500).json({ error: 'Ошибка сервера' });
                    db.run('UPDATE applications SET employer_rating = ?, worker_rated = 1 WHERE id = ?', 
                        [rating, req.params.applicationId], (err) => {
                            if (err) return res.status(500).json({ error: 'Ошибка сервера' });
                            res.json({ message: 'Оценка поставлена' });
                        }
                    );
                });
            }
        );
    });
});

app.post('/api/applications/:applicationId/claim-payment', authenticateToken, (req, res) => {
    db.get('SELECT a.*, t.payment FROM applications a JOIN tasks t ON a.task_id = t.id WHERE a.id = ?', 
        [req.params.applicationId], (err, app) => {
            if (err || !app) return res.status(404).json({ error: 'Отклик не найден' });
            if (app.applicant_id !== req.user.id) return res.status(403).json({ error: 'Нет прав' });
            if (app.payment_claimed) return res.status(400).json({ error: 'Деньги уже получены' });
            if (!app.worker_rated) return res.status(400).json({ error: 'Сначала оцените работодателя' });

            db.run('UPDATE users SET balance = balance + ? WHERE id = ?', [app.payment, req.user.id], (err) => {
                if (err) return res.status(500).json({ error: 'Ошибка сервера' });
                db.run('UPDATE applications SET payment_claimed = 1 WHERE id = ?', [req.params.applicationId], (err) => {
                    if (err) return res.status(500).json({ error: 'Ошибка сервера' });
                    res.json({ message: `Получено ${app.payment} Я баллов!`, amount: app.payment });
                });
            });
        }
    );
});

// ЧАТ
app.get('/api/chat/:taskId', authenticateToken, (req, res) => {
    db.all(`SELECT m.*, u.username as sender FROM chat_messages m JOIN users u ON m.sender_id = u.id 
            WHERE m.task_id = ? ORDER BY m.created_at ASC`, [req.params.taskId], (err, messages) => {
        if (err) return res.status(500).json({ error: 'Ошибка сервера' });
        res.json(messages);
    });
});

app.post('/api/chat/:taskId', authenticateToken, (req, res) => {
    const { text } = req.body;
    if (!text) return res.status(400).json({ error: 'Текст обязателен' });

    db.run('INSERT INTO chat_messages (task_id, sender_id, text) VALUES (?, ?, ?)', 
        [req.params.taskId, req.user.id, text], function(err) {
            if (err) return res.status(500).json({ error: 'Ошибка сервера' });
            res.json({ message: 'Сообщение отправлено' });
        }
    );
});

// ПОДДЕРЖКА
app.get('/api/support/my-messages', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM support_messages WHERE user_id = ? ORDER BY created_at ASC`, 
        [req.user.id], (err, messages) => {
            if (err) return res.status(500).json({ error: 'Ошибка сервера' });
            res.json(messages);
        }
    );
});

app.post('/api/support/send', authenticateToken, (req, res) => {
    const { text } = req.body;
    if (!text) return res.status(400).json({ error: 'Текст обязателен' });

    db.run('INSERT INTO support_messages (user_id, sender_type, text) VALUES (?, ?, ?)', 
        [req.user.id, 'user', text], function(err) {
            if (err) return res.status(500).json({ error: 'Ошибка сервера' });
            res.json({ message: 'Сообщение отправлено' });
        }
    );
});

// АДМИНКА
app.post('/api/admin/login', (req, res) => {
    const { password } = req.body;
    if (password === ADMIN_PASSWORD) {
        const token = jwt.sign({ admin: true }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, success: true });
    } else {
        res.status(401).json({ error: 'Неверный пароль' });
    }
});

app.get('/api/admin/support-tickets', (req, res) => {
    db.all(`SELECT DISTINCT sm.user_id, u.username, 
            (SELECT text FROM support_messages WHERE user_id = sm.user_id ORDER BY created_at DESC LIMIT 1) as last_message,
            (SELECT created_at FROM support_messages WHERE user_id = sm.user_id ORDER BY created_at DESC LIMIT 1) as updated_at
            FROM support_messages sm 
            JOIN users u ON sm.user_id = u.id 
            ORDER BY updated_at DESC`, [], (err, tickets) => {
        if (err) return res.status(500).json({ error: 'Ошибка сервера' });
        res.json(tickets);
    });
});

app.get('/api/admin/support-messages/:userId', (req, res) => {
    db.all(`SELECT * FROM support_messages WHERE user_id = ? ORDER BY created_at ASC`, 
        [req.params.userId], (err, messages) => {
            if (err) return res.status(500).json({ error: 'Ошибка сервера' });
            res.json(messages);
        }
    );
});

app.post('/api/admin/support-reply', (req, res) => {
    const { userId, text } = req.body;
    if (!text || !userId) return res.status(400).json({ error: 'Все поля обязательны' });

    db.run('INSERT INTO support_messages (user_id, sender_type, text) VALUES (?, ?, ?)', 
        [userId, 'admin', text], function(err) {
            if (err) return res.status(500).json({ error: 'Ошибка сервера' });
            res.json({ message: 'Ответ отправлен' });
        }
    );
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => {
    console.log('');
    console.log('🚀 ===================================');
    console.log('🚀 Сервер ЯвДеле запущен!');
    console.log('🚀 ===================================');
    console.log(`🌐 URL: http://localhost:${PORT}`);
    console.log('🚀 ===================================');
    console.log('');
});
