const axios = require('axios');
async function test() {
  try {
    const res = await axios.post('http://localhost:8080/api/auth/login', {
      email: 'viewer1@gmail.com', // Replace with a known user if different
      password: 'password123'
    });
    console.log(res.data);
  } catch (err) {
    console.error(err.response?.data || err.message);
  }
}
test();
