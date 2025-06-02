import React, { useState } from 'react';
import axios from 'axios';

export default function Register() {
  const [form, setForm] = useState({ username: '', email: '', password: '', sensitiveData: '' });
  const [message, setMessage] = useState('');

  function handleChange(e) {
    setForm({ ...form, [e.target.name]: e.target.value });
  }

  async function handleSubmit(e) {
    e.preventDefault();
    try {
      const res = await axios.post('http://localhost:5000/api/register', form);
      setMessage(res.data.message);
      setForm({ username: '', email: '', password: '', sensitiveData: '' });
    } catch (err) {
      setMessage(err.response?.data?.message || 'Error');
    }
  }

  return (
    <div style={{ maxWidth: 400, margin: 'auto', padding: 20 }}>
      <h2>Register</h2>
      <form onSubmit={handleSubmit}>
        <input
          name="username"
          placeholder="Username"
          value={form.username}
          onChange={handleChange}
          required
          style={{ width: '100%', padding: 8, marginBottom: 10 }}
        />
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
        <input
          name="sensitiveData"
          placeholder="Sensitive Data (optional)"
          value={form.sensitiveData}
          onChange={handleChange}
          style={{ width: '100%', padding: 8, marginBottom: 10 }}
        />
        <button type="submit" style={{ padding: 10, width: '100%' }}>Register</button>
      </form>
      <p>{message}</p>
      <p>
        Already have an account? <a href="/">Login here</a>
      </p>
    </div>
  );
}
