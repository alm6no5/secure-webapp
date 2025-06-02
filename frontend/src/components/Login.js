import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

export default function Login() {
  const [form, setForm] = useState({ email: '', password: '' });
  const [message, setMessage] = useState('');
  const navigate = useNavigate();

  function handleChange(e) {
    setForm({ ...form, [e.target.name]: e.target.value });
  }

  async function handleSubmit(e) {
    e.preventDefault();
    try {
      const res = await axios.post('http://localhost:5000/api/login', form, { withCredentials: true });
      setMessage(res.data.message);
      navigate('/register'); // بعد الدخول نوجه المستخدم لصفحة التسجيل (تقدر تغير لصفحة أخرى)
    } catch (err) {
      setMessage(err.response?.data?.message || 'Error');
    }
  }

  return (
    <div style={{ maxWidth: 400, margin: 'auto', padding: 20 }}>
      <h2>Login</h2>
      <form onSubmit={handleSubmit}>
        <input
          name="email"
          type="email"
          placeholder="Email"
          value={form.email}
          onChange={handleChange}
          required
          style={{ width: '100%', padding: 8, marginBottom: 10 }}
        />
        <input
          name="password"
          type="password"
          placeholder="Password"
          value={form.password}
          onChange={handleChange}
          required
          style={{ width: '100%', padding: 8, marginBottom: 10 }}
        />
        <button type="submit" style={{ padding: 10, width: '100%' }}>Login</button>
      </form>
      <p>{message}</p>
      <p>
        Don't have an account? <a href="/register">Register here</a>
      </p>
    </div>
  );
}
