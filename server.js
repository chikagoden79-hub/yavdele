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

// ====================================
// MIDDLEWARE
// ====================================
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// ====================================
// ИНИЦИАЛИЗАЦИЯ БАЗЫ ДАННЫХ
// ====================================
const db = new sqlite3.Database('./yavdele.db', (err) => {
    if (err) {
        console.error('❌ Ошибка подключения к БД:', err);
    } else {
        console.log('✅ Подключено к базе данных SQLite');
        initDatabase();
    }
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

    db.run(`CREATE TABLE IF NOT EXISTS support_tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        subject TEXT NOT NULL,
        message TEXT NOT NULL,
        status TEXT DEFAULT 'open' CHECK(status IN ('open', 'closed')),
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

// ====================================
// АУТЕНТИФИКАЦИЯ
// ====================================
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
            res.json({ token, user: { id: this.lastID, username, type, balance: 0, rating: 5.0, has_premium: false } });
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
        res.json({ token, user: { id: user.id, username: user.username, type: user.type, balance: user.balance, rating: user.rating, has_premium: user.has_premium } });
    });
});

app.get('/api/profile', authenticateToken, (req, res) => {
    db.get('SELECT id, username, type, balance, rating, has_premium FROM users WHERE id = ?', [req.user.id], (err, user) => {
        if (err) return res.status(500).json({ error: 'Ошибка сервера' });
        if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
        res.json(user);
    });
});

// ====================================
// БАЛАНС
// ====================================
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

app.post('/api/premium/buy', authenticateToken, (req, res) => {
    db.get('SELECT balance, has_premium FROM users WHERE id = ?', [req.user.id], (err, user) => {
        if (err) return res.status(500).json({ error: 'Ошибка сервера' });
        if (user.has_premium) return res.status(400).json({ error: 'У вас уже есть ЯвДеле+' });
        if (user.balance < 10000) return res.status(400).json({ error: 'Недостаточно средств. Требуется 10000 Я баллов' });

        db.run('UPDATE users SET balance = balance - 10000, has_premium = 1 WHERE id = ?', [req.user.id], function(err) {
            if (err) return res.status(500).json({ error: 'Ошибка сервера' });
            res.json({ message: 'ЯвДеле+ успешно активирован!', newBalance: user.balance - 10000, has_premium: true });
        });
    });
});

// Благотворительность
app.post('/api/charity/donate', authenticateToken, (req, res) => {
    const { amount, category } = req.body;
    if (!amount || amount < 10) return res.status(400).json({ error: 'Минимальная сумма 10 Я баллов' });

    db.get('SELECT balance FROM users WHERE id = ?', [req.user.id], (err, user) => {
        if (err) return res.status(500).json({ error: 'Ошибка сервера' });
        if (user.balance < amount) return res.status(400).json({ error: 'Недостаточно средств' });

        db.run('UPDATE users SET balance = balance - ? WHERE id = ?', [amount, req.user.id], function(err) {
            if (err) return res.status(500).json({ error: 'Ошибка сервера' });
            res.json({ message: `Спасибо за пожертвование ${amount} Я баллов на ${category}!`, newBalance: user.balance - amount });
        });
    });
});

// ====================================
// ЗАДАНИЯ
// ====================================
app.post('/api/tasks', authenticateToken, (req, res) => {
    const { title, category, location, payment, difficulty, description, requirements, contacts, minRating } = req.body;
    if (!title || !description || !payment || !difficulty || !category) return res.status(400).json({ error: 'Обязательные поля: title, description, payment, difficulty, category' });
    if (payment < 1000) return res.status(400).json({ error: 'Минимальная оплата: 1000 Я баллов' });

    db.get('SELECT balance, has_premium FROM users WHERE id = ?', [req.user.id], (err, user) => {
        if (err) return res.status(500).json({ error: 'Ошибка сервера' });
        if (user.balance < payment) return res.status(400).json({ error: 'Недостаточно средств на балансе' });
        if (minRating > 0 && !user.has_premium) return res.status(400).json({ error: 'Для установки минимального рейтинга нужна подписка ЯвДеле+' });

        db.run('UPDATE users SET balance = balance - ? WHERE id = ?', [payment, req.user.id], function(err) {
            if (err) return res.status(500).json({ error: 'Ошибка сервера' });
            db.run(`INSERT INTO tasks (title, category, location, payment, difficulty, description, requirements, contacts, min_rating, employer_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [title, category, location, payment, difficulty, description, requirements, contacts, minRating || 0, req.user.id],
                function(err) {
                    if (err) {
                        db.run('UPDATE users SET balance = balance + ? WHERE id = ?', [payment, req.user.id]);
                        return res.status(500).json({ error: 'Ошибка создания задания' });
                    }
                    res.json({ id: this.lastID, message: 'Задание успешно создано', newBalance: user.balance - payment });
                }
            );
        });
    });
});

app.get('/api/tasks', (req, res) => {
    const { category, difficulty, minPayment, search } = req.query;
    let query = `SELECT t.*, u.username as employer_name, u.rating as employer_rating FROM tasks t JOIN users u ON t.employer_id = u.id WHERE t.status = 'open'`;
    const params = [];

    if (category && category !== 'all') { query += ' AND t.category = ?'; params.push(category); }
    if (difficulty && difficulty !== 'all') { query += ' AND t.difficulty = ?'; params.push(parseInt(difficulty)); }
    if (minPayment) { query += ' AND t.payment >= ?'; params.push(parseInt(minPayment)); }
    if (search) { query += ' AND (t.title LIKE ? OR t.description LIKE ?)'; params.push(`%${search}%`, `%${search}%`); }

    query += ' ORDER BY t.created_at DESC';
    db.all(query, params, (err, tasks) => {
        if (err) return res.status(500).json({ error: 'Ошибка сервера' });
        res.json(tasks);
    });
});

app.get('/api/tasks/my', authenticateToken, (req, res) => {
    db.all('SELECT * FROM tasks WHERE employer_id = ? ORDER BY created_at DESC', [req.user.id], (err, tasks) => {
        if (err) return res.status(500).json({ error: 'Ошибка сервера' });
        res.json(tasks);
    });
});

app.delete('/api/tasks/:taskId', authenticateToken, (req, res) => {
    const taskId = req.params.taskId;
    db.get('SELECT * FROM tasks WHERE id = ? AND employer_id = ?', [taskId, req.user.id], (err, task) => {
        if (err) return res.status(500).json({ error: 'Ошибка сервера' });
        if (!task) return res.status(404).json({ error: 'Задание не найдено' });
        if (task.status !== 'open') return res.status(400).json({ error: 'Можно удалять только открытые задания' });

        db.run('DELETE FROM tasks WHERE id = ?', [taskId], (err) => {
            if (err) return res.status(500).json({ error: 'Ошибка сервера' });
            db.run('UPDATE users SET balance = balance + ? WHERE id = ?', [task.payment, req.user.id], (err) => {
                if (err) return res.status(500).json({ error: 'Ошибка возврата средств' });
                res.json({ message: 'Задание удалено, средства возвращены', refundedAmount: task.payment });
            });
        });
    });
});

// ====================================
// ОТКЛИКИ
// ====================================
app.post('/api/tasks/:taskId/apply', authenticateToken, (req, res) => {
    const taskId = req.params.taskId;
    db.get('SELECT * FROM applications WHERE task_id = ? AND applicant_id = ?', [taskId, req.user.id], (err, existing) => {
        if (err) return res.status(500).json({ error: 'Ошибка сервера' });
        if (existing) return res.status(400).json({ error: 'Вы уже откликнулись на это задание' });

        db.get('SELECT employer_id FROM tasks WHERE id = ?', [taskId], (err, task) => {
            if (err || !task) return res.status(404).json({ error: 'Задание не найдено' });
            
            db.run('INSERT INTO applications (task_id, applicant_id, employer_id) VALUES (?, ?, ?)', [taskId, req.user.id, task.employer_id], function(err) {
                if (err) return res.status(500).json({ error: 'Ошибка сервера' });
                res.json({ id: this.lastID, message: 'Отклик успешно отправлен' });
            });
        });
    });
});

app.get('/api/tasks/:taskId/applications', authenticateToken, (req, res) => {
    db.all(`SELECT a.*, u.username, u.rating FROM applications a JOIN users u ON a.applicant_id = u.id WHERE a.task_id = ? ORDER BY a.applied_at DESC`,
        [req.params.taskId], (err, applications) => {
            if (err) return res.status(500).json({ error: 'Ошибка сервера' });
            res.json(applications);
        }
    );
});

app.get('/api/applications/my', authenticateToken, (req, res) => {
    db.all(`SELECT a.*, t.title, t.payment, t.description, t.location, t.contacts, u.username as employer_name FROM applications a JOIN tasks t ON a.task_id = t.id JOIN users u ON t.employer_id = u.id WHERE a.applicant_id = ? ORDER BY a.applied_at DESC`,
        [req.user.id], (err, applications) => {
            if (err) return res.status(500).json({ error: 'Ошибка сервера' });
            res.json(applications);
        }
    );
});

// Принять отклик
app.post('/api/applications/:applicationId/accept', authenticateToken, (req, res) => {
    db.get('SELECT * FROM applications WHERE id = ?', [req.params.applicationId], (err, app) => {
        if (err || !app) return res.status(404).json({ error: 'Отклик не найден' });
        if (app.employer_id !== req.user.id) return res.status(403).json({ error: 'Нет прав' });

        db.run('UPDATE applications SET status = ? WHERE id = ?', ['accepted', req.params.applicationId], (err) => {
            if (err) return res.status(500).json({ error: 'Ошибка сервера' });
            db.run('UPDATE tasks SET status = ? WHERE id = ?', ['in_progress', app.task_id], (err) => {
                if (err) return res.status(500).json({ error: 'Ошибка сервера' });
                res.json({ message: 'Отклик принят, ожидайте выполнения' });
            });
        });
    });
});

// Подтвердить выполнение
app.post('/api/applications/:applicationId/confirm-work', authenticateToken, (req, res) => {
    db.get('SELECT * FROM applications WHERE id = ?', [req.params.applicationId], (err, app) => {
        if (err || !app) return res.status(404).json({ error: 'Отклик не найден' });
        if (app.employer_id !== req.user.id) return res.status(403).json({ error: 'Нет прав' });

        db.run('UPDATE applications SET status = ? WHERE id = ?', ['work_done', req.params.applicationId], (err) => {
            if (err) return res.status(500).json({ error: 'Ошибка сервера' });
            res.json({ message: 'Работа подтверждена, теперь можно оценить исполнителя' });
        });
    });
});

// Оценить исполнителя (работодатель оценивает работника)
app.post('/api/applications/:applicationId/rate-worker', authenticateToken, (req, res) => {
    const { rating } = req.body;
    if (!rating || rating < 1 || rating > 5) return res.status(400).json({ error: 'Оценка должна быть от 1 до 5' });

    db.get('SELECT * FROM applications WHERE id = ?', [req.params.applicationId], (err, app) => {
        if (err || !app) return res.status(404).json({ error: 'Отклик не найден' });
        if (app.employer_id !== req.user.id) return res.status(403).json({ error: 'Нет прав' });
        if (app.status !== 'work_done') return res.status(400).json({ error: 'Сначала подтвердите выполнение работы' });

        db.run('UPDATE users SET rating_sum = rating_sum + ?, total_ratings = total_ratings + 1 WHERE id = ?', [rating, app.applicant_id], (err) => {
            if (err) return res.status(500).json({ error: 'Ошибка сервера' });
            db.run('UPDATE users SET rating = CAST(rating_sum AS REAL) / total_ratings WHERE id = ?', [app.applicant_id], (err) => {
                if (err) return res.status(500).json({ error: 'Ошибка сервера' });
                db.run('UPDATE applications SET worker_rating = ?, employer_rated = 1, status = ? WHERE id = ?', [rating, 'completed', req.params.applicationId], (err) => {
                    if (err) return res.status(500).json({ error: 'Ошибка сервера' });
                    db.run('UPDATE tasks SET status = ? WHERE id = ?', ['completed', app.task_id], (err) => {
                        if (err) return res.status(500).json({ error: 'Ошибка сервера' });
                        res.json({ message: 'Оценка поставлена!' });
                    });
                });
            });
        });
    });
});

// Оценить работодателя (работник оценивает работодателя)
app.post('/api/applications/:applicationId/rate-employer', authenticateToken, (req, res) => {
    const { rating } = req.body;
    if (!rating || rating < 1 || rating > 5) return res.status(400).json({ error: 'Оценка должна быть от 1 до 5' });

    db.get('SELECT * FROM applications WHERE id = ?', [req.params.applicationId], (err, app) => {
        if (err || !app) return res.status(404).json({ error: 'Отклик не найден' });
        if (app.applicant_id !== req.user.id) return res.status(403).json({ error: 'Нет прав' });
        if (app.status !== 'completed') return res.status(400).json({ error: 'Работодатель ещё не оценил вас' });

        db.run('UPDATE users SET rating_sum = rating_sum + ?, total_ratings = total_ratings + 1 WHERE id = ?', [rating, app.employer_id], (err) => {
            if (err) return res.status(500).json({ error: 'Ошибка сервера' });
            db.run('UPDATE users SET rating = CAST(rating_sum AS REAL) / total_ratings WHERE id = ?', [app.employer_id], (err) => {
                if (err) return res.status(500).json({ error: 'Ошибка сервера' });
                db.run('UPDATE applications SET employer_rating = ?, worker_rated = 1 WHERE id = ?', [rating, req.params.applicationId], (err) => {
                    if (err) return res.status(500).json({ error: 'Ошибка сервера' });
                    res.json({ message: 'Оценка работодателю поставлена!' });
                });
            });
        });
    });
});

// Получить деньги
app.post('/api/applications/:applicationId/claim-payment', authenticateToken, (req, res) => {
    db.get('SELECT * FROM applications a JOIN tasks t ON a.task_id = t.id WHERE a.id = ?', [req.params.applicationId], (err, app) => {
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
    });
});

app.post('/api/applications/:applicationId/reject', authenticateToken, (req, res) => {
    db.run('UPDATE applications SET status = ? WHERE id = ?', ['rejected', req.params.applicationId], (err) => {
        if (err) return res.status(500).json({ error: 'Ошибка сервера' });
        res.json({ message: 'Отклик отклонен' });
    });
});

app.get('/api/leaderboard', (req, res) => {
    db.all(`SELECT username, rating, total_ratings FROM users WHERE total_ratings > 0 ORDER BY rating DESC, total_ratings DESC LIMIT 50`, [], (err, users) => {
        if (err) return res.status(500).json({ error: 'Ошибка сервера' });
        res.json(users);
    });
});

// ====================================
// ПОДДЕРЖКА
// ====================================
app.post('/api/support', authenticateToken, (req, res) => {
    const { subject, message } = req.body;
    if (!subject || !message) return res.status(400).json({ error: 'Все поля обязательны' });

    db.run('INSERT INTO support_tickets (user_id, subject, message) VALUES (?, ?, ?)', [req.user.id, subject, message], function(err) {
        if (err) return res.status(500).json({ error: 'Ошибка сервера' });
        res.json({ id: this.lastID, message: 'Обращение отправлено! Мы ответим в течение 24 часов.' });
    });
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log('');
    console.log('🚀 ===================================');
    console.log('🚀 Сервер ЯвДеле запущен!');
    console.log('🚀 ===================================');
    console.log(`🌐 URL: http://localhost:${PORT}`);
    console.log(`⚙️ Режим: ${process.env.NODE_ENV || 'development'}`);
    console.log('🚀 ===================================');
    console.log('');
});
