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
const JWT_SECRET = process.env.JWT_SECRET || 'default-secret-key-change-this-in-production';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Y@vD3lE_Admin#9427';

// ====================================
// MIDDLEWARE
// ====================================
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ====================================
// ИНИЦИАЛИЗАЦИЯ БАЗЫ ДАННЫХ
// ====================================
const dbPath = process.env.DATABASE_PATH || path.join(__dirname, 'yavdele.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('❌ Ошибка подключения к БД:', err);
        process.exit(1);
    } else {
        console.log('✅ Подключено к базе данных SQLite');
        initDatabase();
    }
});

function initDatabase() {
    db.run('PRAGMA foreign_keys = ON');

    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        type TEXT NOT NULL CHECK(type IN ('worker', 'employer')),
        balance INTEGER DEFAULT 0,
        rating REAL DEFAULT 5.0,
        total_ratings INTEGER DEFAULT 0,
        rating_sum INTEGER DEFAULT 0,
        completed_tasks INTEGER DEFAULT 0,
        has_premium BOOLEAN DEFAULT 0,
        agreed_to_terms BOOLEAN DEFAULT 0,
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
        worker_id INTEGER NOT NULL,
        status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'accepted', 'rejected', 'completed')),
        worker_rated BOOLEAN DEFAULT 0,
        employer_rated BOOLEAN DEFAULT 0,
        payment_claimed BOOLEAN DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (task_id) REFERENCES tasks(id),
        FOREIGN KEY (worker_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS chat_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id INTEGER NOT NULL,
        sender_id INTEGER NOT NULL,
        sender_name TEXT NOT NULL,
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

    db.run(`CREATE TABLE IF NOT EXISTS charity_donations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        amount INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )`, (err) => {
        if (!err) console.log('✅ Все таблицы инициализированы');
    });
}

// ====================================
// MIDDLEWARE АВТОРИЗАЦИИ
// ====================================
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Требуется авторизация' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Неверный токен' });
        }
        req.user = user;
        next();
    });
}

// ====================================
// HEALTH CHECK
// ====================================
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development'
    });
});

// ====================================
// РЕГИСТРАЦИЯ
// ====================================
app.post('/api/register', async (req, res) => {
    try {
        const { username, password, type, agreedToTerms } = req.body;

        if (!username || !password || !type) {
            return res.status(400).json({ error: 'Все поля обязательны' });
        }

        if (!agreedToTerms) {
            return res.status(400).json({ error: 'Необходимо согласиться с условиями договора' });
        }

        if (type !== 'worker' && type !== 'employer') {
            return res.status(400).json({ error: 'Неверный тип пользователя' });
        }

        if (username.length < 3) {
            return res.status(400).json({ error: 'Имя пользователя должно быть не менее 3 символов' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Пароль должен быть не менее 6 символов' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        
        db.run(
            'INSERT INTO users (username, password, type, agreed_to_terms) VALUES (?, ?, ?, ?)',
            [username, hashedPassword, type, 1],
            function(err) {
                if (err) {
                    if (err.message.includes('UNIQUE')) {
                        return res.status(400).json({ error: 'Пользователь с таким именем уже существует' });
                    }
                    console.error('Ошибка регистрации:', err);
                    return res.status(500).json({ error: 'Ошибка создания пользователя' });
                }

                const token = jwt.sign(
                    { id: this.lastID, username, type },
                    JWT_SECRET,
                    { expiresIn: '30d' }
                );

                res.json({
                    token,
                    user: {
                        id: this.lastID,
                        username,
                        type,
                        balance: 0,
                        rating: 5.0,
                        has_premium: false
                    }
                });
            }
        );
    } catch (error) {
        console.error('Ошибка в /api/register:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ====================================
// ВХОД
// ====================================
app.post('/api/login', (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Все поля обязательны' });
        }

        db.get(
            'SELECT * FROM users WHERE username = ?',
            [username],
            async (err, user) => {
                if (err) {
                    console.error('Ошибка входа:', err);
                    return res.status(500).json({ error: 'Ошибка сервера' });
                }

                if (!user) {
                    return res.status(400).json({ error: 'Неверное имя пользователя или пароль' });
                }

                const validPassword = await bcrypt.compare(password, user.password);
                if (!validPassword) {
                    return res.status(400).json({ error: 'Неверное имя пользователя или пароль' });
                }

                const token = jwt.sign(
                    { id: user.id, username: user.username, type: user.type },
                    JWT_SECRET,
                    { expiresIn: '30d' }
                );

                res.json({
                    token,
                    user: {
                        id: user.id,
                        username: user.username,
                        type: user.type,
                        balance: user.balance,
                        rating: user.rating,
                        has_premium: user.has_premium
                    }
                });
            }
        );
    } catch (error) {
        console.error('Ошибка в /api/login:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ====================================
// ПРОФИЛЬ
// ====================================
app.get('/api/profile', authenticateToken, (req, res) => {
    db.get(
        'SELECT id, username, type, balance, rating, has_premium, completed_tasks FROM users WHERE id = ?',
        [req.user.id],
        (err, user) => {
            if (err) {
                console.error('Ошибка получения профиля:', err);
                return res.status(500).json({ error: 'Ошибка сервера' });
            }
            if (!user) {
                return res.status(404).json({ error: 'Пользователь не найден' });
            }
            res.json(user);
        }
    );
});


// ====================================
// БАЛАНС
// ====================================
app.post('/api/balance/add', authenticateToken, (req, res) => {
    const { amount } = req.body;

    if (!amount || amount < 1000) {
        return res.status(400).json({ error: 'Минимальная сумма пополнения: 1000 Я баллов' });
    }

    db.run(
        'UPDATE users SET balance = balance + ? WHERE id = ?',
        [amount, req.user.id],
        function(err) {
            if (err) {
                console.error('Ошибка пополнения баланса:', err);
                return res.status(500).json({ error: 'Ошибка сервера' });
            }

            db.get(
                'SELECT balance FROM users WHERE id = ?',
                [req.user.id],
                (err, user) => {
                    if (err) {
                        return res.status(500).json({ error: 'Ошибка сервера' });
                    }
                    res.json({ message: 'Баланс успешно пополнен', balance: user.balance });
                }
            );
        }
    );
});

app.post('/api/balance/withdraw', authenticateToken, (req, res) => {
    db.get(
        'SELECT balance, type FROM users WHERE id = ?',
        [req.user.id],
        (err, user) => {
            if (err) {
                return res.status(500).json({ error: 'Ошибка сервера' });
            }

            if (user.type !== 'worker') {
                return res.status(400).json({ error: 'Вывод доступен только для работников' });
            }

            if (user.balance < 3000) {
                return res.status(400).json({ error: 'Недостаточно средств. Минимум для вывода: 3000 Я баллов (300 ₽)' });
            }

            const amount = user.balance;
            const rubles = (amount / 10).toFixed(2);

            db.run(
                'UPDATE users SET balance = 0 WHERE id = ?',
                [req.user.id],
                function(err) {
                    if (err) {
                        return res.status(500).json({ error: 'Ошибка сервера' });
                    }

                    res.json({ 
                        message: `Заявка на вывод ${rubles} ₽ успешно создана. Средства поступят в течение 24 часов.`,
                        withdrawnAmount: amount,
                        rubles: rubles
                    });
                }
            );
        }
    );
});

app.post('/api/premium/buy', authenticateToken, (req, res) => {
    db.get(
        'SELECT balance, has_premium, type FROM users WHERE id = ?',
        [req.user.id],
        (err, user) => {
            if (err) {
                return res.status(500).json({ error: 'Ошибка сервера' });
            }

            if (user.type !== 'employer') {
                return res.status(400).json({ error: 'ЯвДеле+ доступен только для работодателей' });
            }

            if (user.has_premium) {
                return res.status(400).json({ error: 'У вас уже есть ЯвДеле+' });
            }

            if (user.balance < 10000) {
                return res.status(400).json({ error: 'Недостаточно средств. Требуется 10000 Я баллов (1000 ₽)' });
            }

            db.run(
                'UPDATE users SET balance = balance - 10000, has_premium = 1 WHERE id = ?',
                [req.user.id],
                function(err) {
                    if (err) {
                        return res.status(500).json({ error: 'Ошибка сервера' });
                    }

                    res.json({ 
                        message: '⭐ ЯвДеле+ успешно активирован!',
                        newBalance: user.balance - 10000,
                        has_premium: true
                    });
                }
            );
        }
    );
});

// ====================================
// ЗАДАНИЯ
// ====================================
app.post('/api/tasks', authenticateToken, (req, res) => {
    const { title, category, location, payment, difficulty, description, requirements, contacts, minRating } = req.body;

    if (!title || !description || !payment || !difficulty || !category) {
        return res.status(400).json({ error: 'Обязательные поля: название, описание, оплата, сложность, категория' });
    }

    if (payment < 1000) {
        return res.status(400).json({ error: 'Минимальная оплата: 1000 Я баллов (100 ₽)' });
    }

    if (req.user.type !== 'employer') {
        return res.status(400).json({ error: 'Только работодатели могут создавать задания' });
    }

    db.get('SELECT balance, has_premium FROM users WHERE id = ?', [req.user.id], (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Ошибка сервера' });
        }

        if (user.balance < payment) {
            return res.status(400).json({ error: 'Недостаточно средств на балансе' });
        }

        if (minRating > 0 && !user.has_premium) {
            return res.status(400).json({ error: 'Для установки минимального рейтинга нужна подписка ЯвДеле+' });
        }

        if (minRating > 5) {
            return res.status(400).json({ error: 'Максимальный рейтинг - 5.0' });
        }

        if (minRating < 0) {
            return res.status(400).json({ error: 'Минимальный рейтинг не может быть отрицательным' });
        }

        db.run(
            'UPDATE users SET balance = balance - ? WHERE id = ?',
            [payment, req.user.id],
            function(err) {
                if (err) {
                    return res.status(500).json({ error: 'Ошибка сервера' });
                }

                db.run(
                    `INSERT INTO tasks (title, category, location, payment, difficulty, description, requirements, contacts, min_rating, employer_id)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [title, category, location || '', payment, difficulty, description, requirements || '', contacts || '', minRating || 0, req.user.id],
                    function(err) {
                        if (err) {
                            db.run('UPDATE users SET balance = balance + ? WHERE id = ?', [payment, req.user.id]);
                            return res.status(500).json({ error: 'Ошибка создания задания' });
                        }

                        res.json({
                            id: this.lastID,
                            message: 'Задание успешно создано',
                            newBalance: user.balance - payment
                        });
                    }
                );
            }
        );
    });
});

app.get('/api/tasks', (req, res) => {
    const { category, difficulty, minPayment, search } = req.query;
    
    let query = `
        SELECT t.*, u.username as employer_name, u.rating as employer_rating
        FROM tasks t 
        JOIN users u ON t.employer_id = u.id 
        WHERE t.status = 'open'
    `;
    const params = [];

    if (category && category !== 'all') {
        query += ' AND t.category = ?';
        params.push(category);
    }

    if (difficulty && difficulty !== 'all') {
        query += ' AND t.difficulty = ?';
        params.push(parseInt(difficulty));
    }

    if (minPayment && parseInt(minPayment) > 0) {
        query += ' AND t.payment >= ?';
        params.push(parseInt(minPayment));
    }

    if (search) {
        query += ' AND (t.title LIKE ? OR t.description LIKE ?)';
        params.push(`%${search}%`, `%${search}%`);
    }

    query += ' ORDER BY t.created_at DESC LIMIT 100';

    db.all(query, params, (err, tasks) => {
        if (err) {
            console.error('Ошибка получения заданий:', err);
            return res.status(500).json({ error: 'Ошибка сервера' });
        }
        res.json(tasks || []);
    });
});

app.get('/api/tasks/my', authenticateToken, (req, res) => {
    db.all(
        'SELECT * FROM tasks WHERE employer_id = ? ORDER BY created_at DESC',
        [req.user.id],
        (err, tasks) => {
            if (err) {
                return res.status(500).json({ error: 'Ошибка сервера' });
            }
            res.json(tasks || []);
        }
    );
});

app.delete('/api/tasks/:taskId', authenticateToken, (req, res) => {
    const taskId = req.params.taskId;

    db.get('SELECT * FROM tasks WHERE id = ? AND employer_id = ?', [taskId, req.user.id], (err, task) => {
        if (err) {
            return res.status(500).json({ error: 'Ошибка сервера' });
        }

        if (!task) {
            return res.status(404).json({ error: 'Задание не найдено' });
        }

        if (task.status !== 'open') {
            return res.status(400).json({ error: 'Можно удалять только открытые задания' });
        }

        db.get('SELECT COUNT(*) as count FROM applications WHERE task_id = ? AND status = "accepted"', [taskId], (err, result) => {
            if (err) {
                return res.status(500).json({ error: 'Ошибка сервера' });
            }

            if (result.count > 0) {
                return res.status(400).json({ error: 'Нельзя удалить задание с принятыми откликами' });
            }

            db.run('DELETE FROM applications WHERE task_id = ?', [taskId], (err) => {
                if (err) {
                    return res.status(500).json({ error: 'Ошибка сервера' });
                }

                db.run('DELETE FROM tasks WHERE id = ?', [taskId], (err) => {
                    if (err) {
                        return res.status(500).json({ error: 'Ошибка сервера' });
                    }

                    db.run('UPDATE users SET balance = balance + ? WHERE id = ?', [task.payment, req.user.id], (err) => {
                        if (err) {
                            return res.status(500).json({ error: 'Ошибка возврата средств' });
                        }

                        res.json({ 
                            message: `Задание удалено. ${task.payment} Я баллов возвращено на баланс.`,
                            refundedAmount: task.payment
                        });
                    });
                });
            });
        });
    });
});


// ====================================
// ОТКЛИКИ НА ЗАДАНИЯ - ИСПРАВЛЕНО!
// ====================================
app.post('/api/tasks/:taskId/apply', authenticateToken, (req, res) => {
    const taskId = req.params.taskId;

    if (req.user.type !== 'worker') {
        return res.status(400).json({ error: 'Только работники могут откликаться на задания' });
    }

    // Проверяем существующие отклики
    db.get(
        'SELECT * FROM applications WHERE task_id = ? AND worker_id = ?',
        [taskId, req.user.id],
        (err, existing) => {
            if (err) {
                console.error('Ошибка проверки откликов:', err);
                return res.status(500).json({ error: 'Ошибка сервера' });
            }

            if (existing) {
                return res.status(400).json({ error: 'Вы уже откликнулись на это задание' });
            }

            // Получаем инфо о задании и рейтинге работника
            db.get(
                `SELECT t.*, u.rating as worker_rating 
                 FROM tasks t, users u 
                 WHERE t.id = ? AND u.id = ?`,
                [taskId, req.user.id],
                (err, data) => {
                    if (err) {
                        console.error('Ошибка получения данных:', err);
                        return res.status(500).json({ error: 'Ошибка сервера' });
                    }

                    if (!data) {
                        return res.status(404).json({ error: 'Задание не найдено' });
                    }

                    if (data.status !== 'open') {
                        return res.status(400).json({ error: 'Задание уже не доступно' });
                    }

                    if (data.worker_rating < data.min_rating) {
                        return res.status(400).json({ error: 'Ваш рейтинг ниже требуемого для этого задания' });
                    }

                    // Создаём отклик
                    db.run(
                        'INSERT INTO applications (task_id, worker_id, status) VALUES (?, ?, ?)',
                        [taskId, req.user.id, 'pending'],
                        function(err) {
                            if (err) {
                                console.error('Ошибка создания отклика:', err);
                                return res.status(500).json({ error: 'Ошибка сервера' });
                            }
                            
                            console.log(`✅ Отклик создан: ID ${this.lastID}, task ${taskId}, worker ${req.user.id}`);
                            
                            res.json({ 
                                id: this.lastID, 
                                message: 'Отклик успешно отправлен',
                                success: true
                            });
                        }
                    );
                }
            );
        }
    );
});

app.get('/api/tasks/:taskId/applications', authenticateToken, (req, res) => {
    const taskId = req.params.taskId;

    db.get('SELECT employer_id FROM tasks WHERE id = ?', [taskId], (err, task) => {
        if (err) {
            return res.status(500).json({ error: 'Ошибка сервера' });
        }

        if (!task) {
            return res.status(404).json({ error: 'Задание не найдено' });
        }

        if (task.employer_id !== req.user.id) {
            return res.status(403).json({ error: 'Нет доступа' });
        }

        db.all(
            `SELECT a.*, u.username as worker_name, u.rating as worker_rating, t.title as task_title
             FROM applications a 
             JOIN users u ON a.worker_id = u.id 
             JOIN tasks t ON a.task_id = t.id
             WHERE a.task_id = ?
             ORDER BY a.created_at DESC`,
            [taskId],
            (err, applications) => {
                if (err) {
                    return res.status(500).json({ error: 'Ошибка сервера' });
                }
                res.json(applications || []);
            }
        );
    });
});

app.get('/api/applications/my', authenticateToken, (req, res) => {
    db.all(
        `SELECT 
            a.id,
            a.task_id,
            a.status,
            a.worker_rated,
            a.employer_rated,
            a.payment_claimed,
            a.created_at,
            t.title as task_title,
            t.payment as task_payment,
            t.description as task_description,
            t.contacts as task_contacts,
            u.username as employer_name,
            u.rating as employer_rating
         FROM applications a
         JOIN tasks t ON a.task_id = t.id
         JOIN users u ON t.employer_id = u.id
         WHERE a.worker_id = ?
         ORDER BY a.created_at DESC`,
        [req.user.id],
        (err, applications) => {
            if (err) {
                console.error('Ошибка получения откликов:', err);
                return res.status(500).json({ error: 'Ошибка сервера' });
            }
            res.json(applications || []);
        }
    );
});

app.post('/api/applications/:applicationId/accept', authenticateToken, (req, res) => {
    const applicationId = req.params.applicationId;

    db.get(
        `SELECT a.*, t.employer_id, t.status as task_status
         FROM applications a 
         JOIN tasks t ON a.task_id = t.id 
         WHERE a.id = ?`,
        [applicationId],
        (err, application) => {
            if (err) {
                return res.status(500).json({ error: 'Ошибка сервера' });
            }

            if (!application) {
                return res.status(404).json({ error: 'Отклик не найден' });
            }

            if (application.employer_id !== req.user.id) {
                return res.status(403).json({ error: 'Нет прав' });
            }

            if (application.status !== 'pending') {
                return res.status(400).json({ error: 'Отклик уже обработан' });
            }

            db.run(
                'UPDATE applications SET status = "rejected" WHERE task_id = ? AND id != ?',
                [application.task_id, applicationId],
                (err) => {
                    if (err) {
                        return res.status(500).json({ error: 'Ошибка сервера' });
                    }

                    db.run('UPDATE applications SET status = "accepted" WHERE id = ?', [applicationId], (err) => {
                        if (err) {
                            return res.status(500).json({ error: 'Ошибка сервера' });
                        }

                        db.run('UPDATE tasks SET status = "in_progress" WHERE id = ?', [application.task_id], (err) => {
                            if (err) {
                                return res.status(500).json({ error: 'Ошибка сервера' });
                            }

                            res.json({ message: 'Отклик принят! Чат открыт для общения.' });
                        });
                    });
                }
            );
        }
    );
});

app.post('/api/applications/:applicationId/reject', authenticateToken, (req, res) => {
    const applicationId = req.params.applicationId;

    db.get(
        `SELECT a.*, t.employer_id
         FROM applications a 
         JOIN tasks t ON a.task_id = t.id 
         WHERE a.id = ?`,
        [applicationId],
        (err, application) => {
            if (err) {
                return res.status(500).json({ error: 'Ошибка сервера' });
            }

            if (!application) {
                return res.status(404).json({ error: 'Отклик не найден' });
            }

            if (application.employer_id !== req.user.id) {
                return res.status(403).json({ error: 'Нет прав' });
            }

            db.run('UPDATE applications SET status = "rejected" WHERE id = ?', [applicationId], (err) => {
                if (err) {
                    return res.status(500).json({ error: 'Ошибка сервера' });
                }
                res.json({ message: 'Отклик отклонен' });
            });
        }
    );
});

app.post('/api/applications/:applicationId/confirm-work', authenticateToken, (req, res) => {
    const applicationId = req.params.applicationId;

    db.get(
        `SELECT a.*, t.employer_id
         FROM applications a 
         JOIN tasks t ON a.task_id = t.id 
         WHERE a.id = ?`,
        [applicationId],
        (err, application) => {
            if (err) {
                return res.status(500).json({ error: 'Ошибка сервера' });
            }

            if (!application) {
                return res.status(404).json({ error: 'Отклик не найден' });
            }

            if (application.employer_id !== req.user.id) {
                return res.status(403).json({ error: 'Нет прав' });
            }

            if (application.status !== 'accepted') {
                return res.status(400).json({ error: 'Работа еще не принята' });
            }

            db.run('UPDATE applications SET status = "completed" WHERE id = ?', [applicationId], (err) => {
                if (err) {
                    return res.status(500).json({ error: 'Ошибка сервера' });
                }

                db.run('UPDATE tasks SET status = "completed" WHERE id = ?', [application.task_id], (err) => {
                    if (err) {
                        return res.status(500).json({ error: 'Ошибка сервера' });
                    }

                    res.json({ message: 'Работа подтверждена. Теперь вы можете оценить исполнителя.' });
                });
            });
        }
    );
});

app.post('/api/applications/:applicationId/rate-worker', authenticateToken, (req, res) => {
    const applicationId = req.params.applicationId;
    const { rating } = req.body;

    if (!rating || rating < 1 || rating > 5) {
        return res.status(400).json({ error: 'Оценка должна быть от 1 до 5' });
    }

    db.get(
        `SELECT a.*, t.employer_id
         FROM applications a 
         JOIN tasks t ON a.task_id = t.id 
         WHERE a.id = ?`,
        [applicationId],
        (err, application) => {
            if (err) {
                return res.status(500).json({ error: 'Ошибка сервера' });
            }

            if (!application) {
                return res.status(404).json({ error: 'Отклик не найден' });
            }

            if (application.employer_id !== req.user.id) {
                return res.status(403).json({ error: 'Нет прав' });
            }

            if (application.status !== 'completed') {
                return res.status(400).json({ error: 'Работа еще не завершена' });
            }

            if (application.worker_rated) {
                return res.status(400).json({ error: 'Вы уже оценили этого работника' });
            }

            db.run(
                'UPDATE users SET rating_sum = rating_sum + ?, total_ratings = total_ratings + 1, completed_tasks = completed_tasks + 1 WHERE id = ?',
                [rating, application.worker_id],
                (err) => {
                    if (err) {
                        return res.status(500).json({ error: 'Ошибка сервера' });
                    }

                    db.run(
                        'UPDATE users SET rating = CAST(rating_sum AS REAL) / total_ratings WHERE id = ?',
                        [application.worker_id],
                        (err) => {
                            if (err) {
                                return res.status(500).json({ error: 'Ошибка сервера' });
                            }

                            db.run(
                                'UPDATE applications SET worker_rated = 1 WHERE id = ?',
                                [applicationId],
                                (err) => {
                                    if (err) {
                                        return res.status(500).json({ error: 'Ошибка сервера' });
                                    }

                                    res.json({ message: 'Оценка успешно поставлена!' });
                                }
                            );
                        }
                    );
                }
            );
        }
    );
});

app.post('/api/applications/:applicationId/rate-employer', authenticateToken, (req, res) => {
    const applicationId = req.params.applicationId;
    const { rating } = req.body;

    if (!rating || rating < 1 || rating > 5) {
        return res.status(400).json({ error: 'Оценка должна быть от 1 до 5' });
    }

    db.get(
        `SELECT a.*, t.employer_id
         FROM applications a 
         JOIN tasks t ON a.task_id = t.id 
         WHERE a.id = ?`,
        [applicationId],
        (err, application) => {
            if (err) {
                return res.status(500).json({ error: 'Ошибка сервера' });
            }

            if (!application) {
                return res.status(404).json({ error: 'Отклик не найден' });
            }

            if (application.worker_id !== req.user.id) {
                return res.status(403).json({ error: 'Нет прав' });
            }

            if (application.status !== 'completed') {
                return res.status(400).json({ error: 'Работа еще не завершена' });
            }

            if (application.employer_rated) {
                return res.status(400).json({ error: 'Вы уже оценили этого работодателя' });
            }

            db.run(
                'UPDATE users SET rating_sum = rating_sum + ?, total_ratings = total_ratings + 1 WHERE id = ?',
                [rating, application.employer_id],
                (err) => {
                    if (err) {
                        return res.status(500).json({ error: 'Ошибка сервера' });
                    }

                    db.run(
                        'UPDATE users SET rating = CAST(rating_sum AS REAL) / total_ratings WHERE id = ?',
                        [application.employer_id],
                        (err) => {
                            if (err) {
                                return res.status(500).json({ error: 'Ошибка сервера' });
                            }

                            db.run(
                                'UPDATE applications SET employer_rated = 1 WHERE id = ?',
                                [applicationId],
                                (err) => {
                                    if (err) {
                                        return res.status(500).json({ error: 'Ошибка сервера' });
                                    }

                                    res.json({ message: 'Оценка успешно поставлена!' });
                                }
                            );
                        }
                    );
                }
            );
        }
    );
});

app.post('/api/applications/:applicationId/claim-payment', authenticateToken, (req, res) => {
    const applicationId = req.params.applicationId;

    db.get(
        `SELECT a.*, t.payment
         FROM applications a 
         JOIN tasks t ON a.task_id = t.id 
         WHERE a.id = ?`,
        [applicationId],
        (err, application) => {
            if (err) {
                return res.status(500).json({ error: 'Ошибка сервера' });
            }

            if (!application) {
                return res.status(404).json({ error: 'Отклик не найден' });
            }

            if (application.worker_id !== req.user.id) {
                return res.status(403).json({ error: 'Нет прав' });
            }

            if (application.status !== 'completed') {
                return res.status(400).json({ error: 'Работа еще не завершена' });
            }

            if (!application.employer_rated) {
                return res.status(400).json({ error: 'Сначала оцените работодателя' });
            }

            if (application.payment_claimed) {
                return res.status(400).json({ error: 'Оплата уже получена' });
            }

            db.run(
                'UPDATE users SET balance = balance + ? WHERE id = ?',
                [application.payment, req.user.id],
                (err) => {
                    if (err) {
                        return res.status(500).json({ error: 'Ошибка сервера' });
                    }

                    db.run(
                        'UPDATE applications SET payment_claimed = 1 WHERE id = ?',
                        [applicationId],
                        (err) => {
                            if (err) {
                                return res.status(500).json({ error: 'Ошибка сервера' });
                            }

                            res.json({ 
                                message: `Поздравляем! Вы получили ${application.payment} Я баллов (${(application.payment / 10).toFixed(0)} ₽)`,
                                amount: application.payment
                            });
                        }
                    );
                }
            );
        }
    );
});


// ====================================
// ЧАТ
// ====================================
app.get('/api/chat/:taskId', authenticateToken, (req, res) => {
    const taskId = req.params.taskId;

    db.get(
        `SELECT t.employer_id, a.worker_id
         FROM tasks t
         LEFT JOIN applications a ON t.id = a.task_id AND (a.status = 'accepted' OR a.status = 'completed')
         WHERE t.id = ?`,
        [taskId],
        (err, access) => {
            if (err) {
                return res.status(500).json({ error: 'Ошибка сервера' });
            }

            if (!access) {
                return res.status(404).json({ error: 'Задание не найдено' });
            }

            if (access.employer_id !== req.user.id && access.worker_id !== req.user.id) {
                return res.status(403).json({ error: 'Нет доступа к чату' });
            }

            db.all(
                'SELECT * FROM chat_messages WHERE task_id = ? ORDER BY created_at ASC',
                [taskId],
                (err, messages) => {
                    if (err) {
                        return res.status(500).json({ error: 'Ошибка сервера' });
                    }
                    res.json(messages || []);
                }
            );
        }
    );
});

app.post('/api/chat/:taskId', authenticateToken, (req, res) => {
    const taskId = req.params.taskId;
    const { text } = req.body;

    if (!text || text.trim().length === 0) {
        return res.status(400).json({ error: 'Сообщение не может быть пустым' });
    }

    db.get(
        `SELECT t.employer_id, a.worker_id
         FROM tasks t
         LEFT JOIN applications a ON t.id = a.task_id AND (a.status = 'accepted' OR a.status = 'completed')
         WHERE t.id = ?`,
        [taskId],
        (err, access) => {
            if (err) {
                return res.status(500).json({ error: 'Ошибка сервера' });
            }

            if (!access) {
                return res.status(404).json({ error: 'Задание не найдено' });
            }

            if (access.employer_id !== req.user.id && access.worker_id !== req.user.id) {
                return res.status(403).json({ error: 'Нет доступа к чату' });
            }

            db.run(
                'INSERT INTO chat_messages (task_id, sender_id, sender_name, text) VALUES (?, ?, ?, ?)',
                [taskId, req.user.id, req.user.username, text.trim()],
                function(err) {
                    if (err) {
                        return res.status(500).json({ error: 'Ошибка сервера' });
                    }

                    res.json({ id: this.lastID, message: 'Сообщение отправлено' });
                }
            );
        }
    );
});

// ====================================
// ПОДДЕРЖКА
// ====================================
app.get('/api/support/my-messages', authenticateToken, (req, res) => {
    db.all(
        'SELECT * FROM support_messages WHERE user_id = ? ORDER BY created_at ASC',
        [req.user.id],
        (err, messages) => {
            if (err) {
                return res.status(500).json({ error: 'Ошибка сервера' });
            }
            res.json(messages || []);
        }
    );
});

app.post('/api/support/send', authenticateToken, (req, res) => {
    const { text } = req.body;

    if (!text || text.trim().length === 0) {
        return res.status(400).json({ error: 'Сообщение не может быть пустым' });
    }

    db.run(
        'INSERT INTO support_messages (user_id, sender_type, text) VALUES (?, ?, ?)',
        [req.user.id, 'user', text.trim()],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Ошибка сервера' });
            }

            res.json({ id: this.lastID, message: 'Сообщение отправлено. Мы ответим в ближайшее время.' });
        }
    );
});

// ====================================
// БЛАГОТВОРИТЕЛЬНОСТЬ
// ====================================
app.post('/api/charity/donate', authenticateToken, (req, res) => {
    const { amount } = req.body;

    if (amount < 0) {
        return res.status(400).json({ error: 'Некорректная сумма' });
    }

    if (amount === 0) {
        return res.json({ message: 'Спасибо за внимание!' });
    }

    db.get('SELECT balance FROM users WHERE id = ?', [req.user.id], (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Ошибка сервера' });
        }

        if (user.balance < amount) {
            return res.status(400).json({ error: 'Недостаточно средств' });
        }

        db.run(
            'UPDATE users SET balance = balance - ? WHERE id = ?',
            [amount, req.user.id],
            (err) => {
                if (err) {
                    return res.status(500).json({ error: 'Ошибка сервера' });
                }

                db.run(
                    'INSERT INTO charity_donations (user_id, amount) VALUES (?, ?)',
                    [req.user.id, amount],
                    (err) => {
                        if (err) {
                            return res.status(500).json({ error: 'Ошибка сервера' });
                        }

                        res.json({ 
                            message: `Спасибо за пожертвование ${amount} Я баллов!`,
                            newBalance: user.balance - amount
                        });
                    }
                );
            }
        );
    });
});

// ====================================
// РЕЙТИНГ
// ====================================
app.get('/api/leaderboard', (req, res) => {
    db.all(
        `SELECT username, type, rating, total_ratings, completed_tasks
         FROM users 
         WHERE total_ratings > 0 
         ORDER BY rating DESC, total_ratings DESC, completed_tasks DESC
         LIMIT 100`,
        [],
        (err, users) => {
            if (err) {
                return res.status(500).json({ error: 'Ошибка сервера' });
            }
            res.json(users || []);
        }
    );
});

// ====================================
// АДМИН-ПАНЕЛЬ
// ====================================
app.post('/api/admin/login', (req, res) => {
    const { password } = req.body;
    if (password === ADMIN_PASSWORD) {
        res.json({ success: true });
    } else {
        res.json({ success: false });
    }
});

app.get('/api/admin/support-tickets', (req, res) => {
    db.all(
        `SELECT 
            sm.user_id,
            u.username,
            MAX(sm.created_at) as updated_at,
            (SELECT text FROM support_messages WHERE user_id = sm.user_id ORDER BY created_at DESC LIMIT 1) as last_message
         FROM support_messages sm
         JOIN users u ON sm.user_id = u.id
         GROUP BY sm.user_id
         ORDER BY updated_at DESC`,
        [],
        (err, tickets) => {
            if (err) {
                return res.status(500).json({ error: 'Ошибка сервера' });
            }
            res.json(tickets || []);
        }
    );
});

app.get('/api/admin/support-messages/:userId', (req, res) => {
    const userId = req.params.userId;

    db.all(
        'SELECT * FROM support_messages WHERE user_id = ? ORDER BY created_at ASC',
        [userId],
        (err, messages) => {
            if (err) {
                return res.status(500).json({ error: 'Ошибка сервера' });
            }
            res.json(messages || []);
        }
    );
});

app.post('/api/admin/support-reply', (req, res) => {
    const { userId, text } = req.body;

    if (!text || text.trim().length === 0) {
        return res.status(400).json({ error: 'Сообщение не может быть пустым' });
    }

    db.run(
        'INSERT INTO support_messages (user_id, sender_type, text) VALUES (?, ?, ?)',
        [userId, 'admin', text.trim()],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Ошибка сервера' });
            }

            res.json({ id: this.lastID, message: 'Ответ отправлен' });
        }
    );
});

// ====================================
// ГЛАВНАЯ СТРАНИЦА
// ====================================
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('*', (req, res) => {
    if (req.path.startsWith('/api/')) {
        res.status(404).json({ error: 'API endpoint not found' });
    } else {
        res.sendFile(path.join(__dirname, 'public', 'index.html'));
    }
});

// ====================================
// ОБРАБОТКА ОШИБОК
// ====================================
app.use((err, req, res, next) => {
    console.error('Необработанная ошибка:', err.stack);
    res.status(500).json({ error: 'Что-то пошло не так!' });
});

// ====================================
// ЗАПУСК СЕРВЕРА
// ====================================
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log('');
    console.log('🚀 ===================================');
    console.log('🚀 Сервер ЯвДеле запущен!');
    console.log('🚀 ===================================');
    console.log(`🌐 URL: http://localhost:${PORT}`);
    console.log(`⚙️ Режим: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🔐 JWT Secret: ${JWT_SECRET === 'default-secret-key-change-this-in-production' ? '⚠️ ИСПОЛЬЗУЕТСЯ ДЕФОЛТНЫЙ' : '✅ Настроен'}`);
    console.log(`👤 Админ пароль: ${ADMIN_PASSWORD}`);
    console.log('🚀 ===================================');
    console.log('');
}).on('error', (err) => {
    console.error('❌ Ошибка запуска сервера:', err);
    process.exit(1);
});

// Graceful shutdown
const gracefulShutdown = () => {
    console.log('\n🛑 Получен сигнал завершения. Закрываю сервер...');
    
    server.close(() => {
        console.log('✅ HTTP сервер закрыт');
        
        db.close((err) => {
            if (err) {
                console.error('❌ Ошибка закрытия БД:', err);
                process.exit(1);
            } else {
                console.log('✅ База данных закрыта');
                process.exit(0);
            }
        });
    });

    setTimeout(() => {
        console.error('⚠️ Принудительное завершение...');
        process.exit(1);
    }, 10000);
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

process.on('uncaughtException', (err) => {
    console.error('❌ Необработанное исключение:', err);
    gracefulShutdown();
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Необработанное отклонение промиса:', reason);
});
