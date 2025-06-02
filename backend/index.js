const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');

const { PORT, MONGO_URI, JWT_SECRET } = require('./config');
const User = require('./models/User');
const { hashPassword, verifyPassword } = require('./utils/hash');
const { encrypt, decrypt } = require('./utils/encryption');
const { isValidEmail, isValidPassword, sanitizeInput } = require('./utils/validation');
const { authenticateToken, authorizeRoles } = require('./middleware/auth');

const app = express();

// أمان HTTP headers
app.use(helmet());

// السماح بالطلبات من الواجهة الأمامية (React) مع تمكين الكوكيز (credentials)
app.use(cors({ origin: 'http://localhost:3000', credentials: true }));

app.use(express.json());
app.use(cookieParser());

// تحديد معدل الطلبات لمنع هجمات brute force
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 دقيقة
  max: 100, // 100 طلب لكل IP خلال الـ 15 دقيقة
  message: 'Too many requests, please try again later.'
});
app.use(limiter);

// الاتصال بقاعدة البيانات MongoDB
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// API لتسجيل مستخدم جديد
app.post('/api/register', async (req, res) => {
  try {
    let { username, email, password, sensitiveData } = req.body;

    // تنظيف المدخلات
    username = sanitizeInput(username);
    email = sanitizeInput(email);

    if (!username || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    // التحقق من صحة البريد وكلمة المرور
    if (!isValidEmail(email)) {
      return res.status(400).json({ message: 'Invalid email format' });
    }
    if (!isValidPassword(password)) {
      return res.status(400).json({ message: 'Password does not meet complexity requirements' });
    }

    // التأكد من عدم وجود مستخدم بنفس البريد أو الاسم
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(409).json({ message: 'Username or email already exists' });
    }

    // تجزئة كلمة المرور
    const passwordHash = await hashPassword(password);

    // تشفير البيانات الحساسة (اختياري)
    let encryptedData = sensitiveData ? encrypt(sanitizeInput(sensitiveData)) : undefined;

    // إنشاء المستخدم
    const user = new User({
      username,
      email,
      passwordHash,
      role: 'user',
      sensitiveDataEncrypted: encryptedData
    });

    await user.save();

    res.status(201).json({ message: 'User registered successfully' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// API لتسجيل الدخول
app.post('/api/login', async (req, res) => {
  try {
    let { email, password } = req.body;
    email = sanitizeInput(email);

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // التحقق من كلمة المرور
    const validPass = await verifyPassword(password, user.passwordHash);
    if (!validPass) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // إنشاء JWT مع دور المستخدم وصلاحية لمدة ساعة
    const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });

    // إرسال التوكن في كوكي httpOnly لتقليل خطر سرقته
    res.cookie('token', token, {
      httpOnly: true,
      secure: false, // غير مفعل للـ http، فعّل لو تستخدم https
      sameSite: 'strict',
      maxAge: 3600000 // 1 ساعة
    });

    res.json({ message: 'Login successful', token });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// API لجلب بيانات المستخدم (محمي بتوثيق JWT)
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-passwordHash');
    if (!user) return res.status(404).json({ message: 'User not found' });

    // فك التشفير لبيانات حساسة
    let sensitiveData = null;
    if (user.sensitiveDataEncrypted) {
      sensitiveData = decrypt(user.sensitiveDataEncrypted);
    }

    res.json({ user, sensitiveData });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// API لتسجيل الخروج (مسح كوكي التوكن)
app.post('/api/logout', (req, res) => {
  res.clearCookie('token', { httpOnly: true, sameSite: 'strict' });
  res.json({ message: 'Logged out' });
});

// مثال API محمي يحتاج دور admin (حذف مستخدم)
app.delete('/api/admin/user/:id', authenticateToken, authorizeRoles('admin'), async (req, res) => {
  try {
    const userId = req.params.id;
    if (!userId) return res.status(400).json({ message: 'User ID is required' });

    const user = await User.findByIdAndDelete(userId);
    if (!user) return res.status(404).json({ message: 'User not found' });

    res.json({ message: 'User deleted' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
