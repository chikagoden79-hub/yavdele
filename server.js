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
    // Включаем внешние ключи
    db.run('PRAGMA foreign_keys = ON');

    // Таблица пользователей
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
    )`, (err) => {
        if (err) console.error('❌ Ошибка создания таблицы users:', err);
    });

    // Таблица заданий
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
    )`, (err) => {
        if (err) console.error('❌ Ошибка создания таблицы tasks:', err);
    });

    // Таблица откликов
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
    )`, (err) => {
        if (err) console.error('❌ Ошибка создания таблицы applications:', err);
    });

    // Таблица чатов
    db.run(`CREATE TABLE IF NOT EXISTS chat_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id INTEGER NOT NULL,
        sender_id INTEGER NOT NULL,
        sender_name TEXT NOT NULL,
        text TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (task_id) REFERENCES tasks(id),
        FOREIGN KEY (sender_id) REFERENCES users(id)
    )`, (err) => {
        if (err) console.error('❌ Ошибка создания таблицы chat_messages:', err);
    });

    // Таблица обращений в поддержку
    db.run(`CREATE TABLE IF NOT EXISTS support_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        sender_type TEXT NOT NULL CHECK(sender_type IN ('user', 'admin')),
        text TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )`, (err) => {
        if (err) console.error('❌ Ошибка создания таблицы support_messages:', err);
    });

    // Таблица благотворительности
    db.run(`CREATE TABLE IF NOT EXISTS charity_donations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        amount INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )`, (err) => {
        if (err) console.error('❌ Ошибка создания таблицы charity_donations:', err);
        else console.log('✅ Все таблицы базы данных инициализированы');
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
// API МАРШРУТЫ - АУТЕНТИФИКАЦИЯ
// ====================================

// Регистрация
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

// Вход
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

// Получить профиль
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
// API МАРШРУТЫ - БАЛАНС
// ====================================

// Пополнить баланс
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
                        console.error('Ошибка получения баланса:', err);
                        return res.status(500).json({ error: 'Ошибка сервера' });
                    }
                    res.json({ 
                        message: 'Баланс успешно пополнен',
                        balance: user.balance 
                    });
                }
            );
        }
    );
});

// Вывести деньги
app.post('/api/balance/withdraw', authenticateToken, (req, res) => {
    db.get(
        'SELECT balance, type FROM users WHERE id = ?',
        [req.user.id],
        (err, user) => {
            if (err) {
                console.error('Ошибка вывода:', err);
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
                        console.error('Ошибка обнуления баланса:', err);
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

// Купить премиум
app.post('/api/premium/buy', authenticateToken, (req, res) => {
    db.get(
        'SELECT balance, has_premium, type FROM users WHERE id = ?',
        [req.user.id],
        (err, user) => {
            if (err) {
                console.error('Ошибка покупки премиума:', err);
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
                        console.error('Ошибка активации премиума:', err);
                        return res.status(500).json({ error: 'Ошибка сервера' });
                    }

                    res.json({ 
                        message: '⭐ ЯвДеле+ успешно активирован! Теперь вы можете устанавливать минимальный рейтинг для исполнителей.',
                        newBalance: user.balance - 10000,
                        has_premium: true
                    });
                }
            );
        }
    );
});

// ====================================
// API МАРШРУТЫ - ЗАДАНИЯ
// ====================================

// Создать задание
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
            console.error('Ошибка создания задания:', err);
            return res.status(500).json({ error: 'Ошибка сервера' });
        }

        if (user.balance < payment) {
            return res.status(400).json({ error: 'Недостаточно средств на балансе' });
        }

        if (minRating > 0 && !user.has_premium) {
            return res.status(400).json({ error: 'Для установки минимального рейтинга нужна подписка ЯвДеле+' });
        }

        db.run(
            'UPDATE users SET balance = balance - ? WHERE id = ?',
            [payment, req.user.id],
            function(err) {
                if (err) {
                    console.error('Ошибка списания средств:', err);
                    return res.status(500).json({ error: 'Ошибка сервера' });
                }

                db.run(
                    `INSERT INTO tasks (title, category, location, payment, difficulty, description, requirements, contacts, min_rating, employer_id)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [title, category, location || '', payment, difficulty, description, requirements || '', contacts || '', minRating || 0, req.user.id],
                    function(err) {
                        if (err) {
                            db.run('UPDATE users SET balance = balance + ? WHERE id = ?', [payment, req.user.id]);
                            console.error('Ошибка вставки задания:', err);
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

// Получить все задания
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

// Получить мои задания
app.get('/api/tasks/my', authenticateToken, (req, res) => {
    db.all(
        'SELECT * FROM tasks WHERE employer_id = ? ORDER BY created_at DESC',
        [req.user.id],
        (err, tasks) => {
            if (err) {
                console.error('Ошибка получения моих заданий:', err);
                return res.status(500).json({ error: 'Ошибка сервера' });
            }
            res.json(tasks || []);
        }
    );
});

// Удалить задание
app.delete('/api/tasks/:taskId', authenticateToken, (req, res) => {
    const taskId = req.params.taskId;

    db.get('SELECT * FROM tasks WHERE id = ? AND employer_id = ?', [taskId, req.user.id], (err, task) => {
        if (err) {
            console.error('Ошибка удаления задания:', err);
            return res.status(500).json({ error: 'Ошибка сервера' });
        }

        if (!task) {
            return res.status(404).json({ error: 'Задание не найдено' });
        }

        if (task.status !== 'open') {
            return res.status(400).json({ error: 'Можно удалять только открытые задания без принятых откликов' });
        }

        db.get('SELECT COUNT(*) as count FROM applications WHERE task_id = ? AND status = "accepted"', [taskId], (err, result) => {
            if (err) {
                console.error('Ошибка проверки откликов:', err);
                return res.status(500).json({ error: 'Ошибка сервера' });
            }

            if (result.count > 0) {
                return res.status(400).json({ error: 'Нельзя удалить задание с принятыми откликами' });
            }

            db.run('DELETE FROM applications WHERE task_id = ?', [taskId], (err) => {
                if (err) {
                    console.error('Ошибка удаления откликов:', err);
                    return res.status(500).json({ error: 'Ошибка сервера' });
                }

                db.run('DELETE FROM tasks WHERE id = ?', [taskId], (err) => {
                    if (err) {
                        console.error('Ошибка удаления задания из БД:', err);
                        return res.status(500).json({ error: 'Ошибка сервера' });
                    }

                    db.run('UPDATE users SET balance = balance + ? WHERE id = ?', [task.payment, req.user.id], (err) => {
                        if (err) {
                            console.error('Ошибка возврата средств:', err);
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
// ОСТАЛЬНЫЕ API (сокращено для экономии места)
// ====================================

// ... (откл��ки, чат, поддержка, благотворительность, рейтинг, админ-панель)
// Полный код слишком длинный, продолжу в следующем файле

// ====================================
// ГЛАВНАЯ СТРАНИЦА
// ====================================
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Обработка всех остальных маршрутов для SPA
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

    // Принудительное завершение через 10 секунд
    setTimeout(() => {
        console.error('⚠️ Принудительное завершение...');
        process.exit(1);
    }, 10000);
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

// Обработка необработанных исключений
process.on('uncaughtException', (err) => {
    console.error('❌ Необработанное исключение:', err);
    gracefulShutdown();
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Необработанное отклонение промиса:', reason);
});
