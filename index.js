const fastify = require('fastify')({
  logger: true,
  bodyLimit: 10485760 // 10 MB
});

const mysql = require('mysql');
const { promisify } = require('util');
const cors = require('@fastify/cors');
const fastifyMultipart = require('@fastify/multipart');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fastifyJwt = require('@fastify/jwt');
const fs = require('fs');
const path = require('path');
const ExcelJS = require('exceljs');
// CORS setup
fastify.register(cors, {
  origin: '*',
  methods: ['GET', 'PUT', 'POST', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
});
     
// Multipart form handling
fastify.register(fastifyMultipart);
fastify.register(fastifyJwt, {
  secret: 'your_secret_key'
});
// Serve static files from a directory (e.g., public)
fastify.register(require('@fastify/static'), {
  root: path.join(__dirname, 'public'),
  prefix: '/', // Optional: Set the URL prefix for serving static files
});


// MySQL connection setup
const connection = mysql.createConnection({
  host: 'localhost',
  port: '3305',
  user: 'root',
  password: '00000',
  database: 'activity'
});

connection.connect(err => {
  if (err) {
    console.error('Error connecting to database:', err);
    return;
  }
  console.log('Connected to MySQL database');
});

const query = promisify(connection.query).bind(connection);

// Route to handle user registration
fastify.post('/register', async (request, reply) => {
  try {
    const { username, password, name, user_group } = request.body;
    const existingUser = await query('SELECT * FROM loginadmin WHERE username = ?', [username]);
    if (existingUser.length > 0) {
      return reply.code(400).send({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await query('INSERT INTO loginadmin (username, password, name, user_group) VALUES (?, ?, ?, ?)', [username, hashedPassword, name, user_group]);
    const token = jwt.sign({ username }, 'your_secret_key');

    reply.code(201).send({ message: 'User registered successfully', token });
  } catch (error) {
    console.error('Error registering user:', error);
    reply.code(500).send({ message: 'Internal Server Error' });
  }
});

// Route to handle user login
fastify.post('/login', async (request, reply) => {
  try {
    const { username, password } = request.body;
    const user = await query('SELECT * FROM loginadmin WHERE username = ?', [username]);
    if (user.length === 0) {
      return reply.code(401).send({ message: 'Invalid username or password' });
    }

    const isPasswordValid = await bcrypt.compare(password, user[0].password);
    if (!isPasswordValid) {
      return reply.code(401).send({ message: 'Invalid username or password' });
    }

    const token = jwt.sign({ id: user[0].id, username: user[0].username,name: user[0].name }, 'your_secret_key');
    reply.send({ token,username : user[0].username , name:user[0].name, id: user[0].id  });
  } catch (error) {
    console.error('Error logging in user:', error);
    reply.code(500).send({ message: 'Internal Server Error' });
  }
});

// Protected route
fastify.get('/protected', async (request, reply) => {
  try {
    await request.jwtVerify();
    reply.send({ message: 'Protected resource accessed successfully' });
  } catch (error) {
    reply.code(401).send({ message: 'Unauthorized' });
  }
});
// Route to fetch activities
fastify.get('/activities', async (request, reply) => {
  const search = request.query.search || ""; // Get the search query parameter

  try {
    const queryStr = `
      SELECT id, namegroup, nameactivity, day_month_year, time, agency, day_timepost, details, type, importance, image 
      FROM post_activity 
      WHERE namegroup LIKE ? OR nameactivity LIKE ? OR details LIKE ?
    `;
    const searchQuery = `%${search}%`; // Create a search pattern

    const activities = await query(queryStr, [searchQuery, searchQuery, searchQuery]);

    if (!Array.isArray(activities)) {
      throw new TypeError('Query result is not an array');
    }

    const activitypost = activities.map(post => ({
      id: post.id,
      namegroup: post.namegroup,
      nameactivity: post.nameactivity,
      day_month_year: post.day_month_year,
      time: post.time,
      agency: post.agency,
      details: post.details,
      type: post.type,
      day_timepost: post.day_timepost,
      importance: post.importance,
      image: `${post.image}`,
    }));
    reply.send(activitypost);
  } catch (error) {
    console.error('Error fetching activities:', error);
    reply.code(500).send({ message: 'Internal Server Error' });
  }
});


// Route to add a new activity
fastify.post('/activities', async (request, reply) => {
  const parts = request.parts();
  const fields = {};
  let imageBase64 = null;

  for await (const part of parts) {
    if (part.file) {
      const buffers = [];
      for await (const chunk of part.file) {
        buffers.push(chunk);
      }
      const imageBuffer = Buffer.concat(buffers);
      const mimeType = part.mimetype;

      if (mimeType !== 'image/jpeg' && mimeType !== 'image/png') {
        return reply.status(400).send({ message: 'Invalid file type. Only .jpg and .png are allowed.' });
      }

      imageBase64 = `data:${mimeType};base64,${imageBuffer.toString('base64')}`;
    } else {
      fields[part.fieldname] = part.value;
    }
  }

  const { namegroup, nameactivity, day_month_year, time, details, type, importance, agency } = fields;

  if (!namegroup || !nameactivity || !day_month_year || !time || !details || !imageBase64) {
    return reply.status(400).send({ message: 'Missing required fields' });
  }

  const validImportanceValues = ['กิจกรรมสำคัญ', 'ไม่เป็นกิจกรรมสำคัญ'];
  if (!validImportanceValues.includes(importance)) {
    return reply.status(400).send({ message: 'Invalid importance value' });
  }

  try {
    await query(
      'INSERT INTO post_activity (namegroup, nameactivity, day_month_year, time, details, image, type, agency, importance) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [namegroup, nameactivity, day_month_year, time, details, imageBase64, type, agency, importance]
    );
    reply.code(201).send({ message: 'Activity added successfully' });
  } catch (error) {
    console.error('Error adding activity:', error);
    reply.status(500).send({ message: 'Internal Server Error' });
  }
});

// Route to delete an activity by ID
fastify.delete('/activities/:id', async (request, reply) => {
  const { id } = request.params;

  try {
    // Execute the DELETE query
    await query('DELETE FROM post_activity WHERE id = ?', [id]);
    reply.send({ message: 'Activity deleted successfully' });
  } catch (error) {
    console.error('Error deleting activity:', error);
    reply.code(500).send({ message: 'Internal Server Error' });
  }
});

// Route to update an activity by ID
fastify.put('/activities/:id', async (request, reply) => {
  const { id } = request.params;
  const { namegroup, nameactivity, day_month_year, time, details, type, importance, agency, image } = request.body;

  if (!namegroup || !nameactivity || !day_month_year || !time || !details || !type || !agency || !importance || !image) {
    return reply.status(400).send({ message: 'Missing required fields' });
  }

  const validImportanceValues = ['กิจกรรมสำคัญ', 'ไม่เป็นกิจกรรมสำคัญ'];
  if (!validImportanceValues.includes(importance)) {
    return reply.status(400).send({ message: 'Invalid importance value' });
  }

  try {
    await query(
      'UPDATE post_activity SET namegroup = ?, nameactivity = ?, day_month_year = ?, time = ?, details = ?, type = ?, agency = ?, importance = ?, image = ? WHERE id = ?',
      [namegroup, nameactivity, day_month_year, time, details, type, agency, importance, image, id]
    );
    reply.send({ message: 'Activity updated successfully' });
  } catch (error) {
    console.error('Error updating activity:', error);
    reply.status(500).send({ message: 'Internal Server Error' });
  }
});

// Route to handle user image uploads
fastify.post('/user/:id/upload-image', async (request, reply) => {
  const { id } = request.params;
  const parts = request.parts();
  let imageBase64 = null;

  for await (const part of parts) {
    if (part.file) {
      const buffers = [];
      for await (const chunk of part.file) {
        buffers.push(chunk);
      }
      const imageBuffer = Buffer.concat(buffers);
      const mimeType = part.mimetype;

      if (mimeType !== 'image/jpeg' && mimeType !== 'image/png') {
        return reply.status(400).send({ message: 'Invalid file type. Only .jpg and .png are allowed.' });
      }

      imageBase64 = `data:${mimeType};base64,${imageBuffer.toString('base64')}`;
    } else {
      return reply.status(400).send({ message: 'No file provided' });
    }
  }

  if (!imageBase64) {
    return reply.status(400).send({ message: 'No file uploaded' });
  }

  try {
    await query('UPDATE loginadmin SET image = ? WHERE id = ?', [imageBase64, id]);
    reply.send({ message: 'Image uploaded successfully', image: imageBase64 });
  } catch (error) {
    console.error('Error uploading image:', error);
    reply.status(500).send({ message: 'Internal Server Error' });
  }
});

// Route to fetch user data by ID, including profile image
fastify.get('/user/:id', async (request, reply) => {
  const { id } = request.params;

  try {
    const rows = await query('SELECT username, name, image FROM loginadmin WHERE id = ?', [id]);
    if (rows.length === 0) {
      reply.status(404).send({ error: 'User not found' });
    } else {
      const user = rows[0];
      // Check if the user has a profile image
      if (user.image) {
        // If user has a profile image, send the user data including the image
        // Also, convert the image field to text if it's a binary or blob type
        const userData = { ...user };
        if (typeof user.image !== 'string') {
          userData.image = user.image.toString('utf8');
        }
        reply.send(userData);
      } else {
        // If user does not have a profile image, send the user data without the image
        // Additionally, send a placeholder or default image URL
        reply.send({ ...user, image: '/default-profile-image.jpg' });
      }
    }
  } catch (err) {
    console.error('Error fetching user data:', err);
    reply.status(500).send({ error: 'Internal server error' });
  }
});

// Route to generate and download the Excel file
fastify.get('/download-user-activities', async (request, reply) => {
  const { selectedActivity } = request.query; // Get the selected activity from the query parameters
  
  try {
    // Fetch data from the user_activity table and join with post_activity table based on nameactivity
    const userActivities = await query(`
      SELECT
        ua.idup,
        ua.mail,
        ua.name,
        ua.user_group,
        ua.branch,
        ua.nameactivity AS ua_nameactivity,
        pa.id AS post_id,
        pa.nameactivity AS pa_nameactivity,
        pa.namegroup,
        pa.day_month_year,
        pa.time,
        pa.agency,
        pa.details,
        pa.type,
        pa.importance,
        pa.image
      FROM user_activity ua
      INNER JOIN post_activity pa ON ua.nameactivity = pa.nameactivity
    `);

    // Create a new workbook and worksheet
    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('User Activities');

 
    // Add column headers
    worksheet.columns = [
     
      { header: 'รหัสนิสิต', key: 'idup', width: 10, },
      { header: 'อีเมลมหาลัย', key: 'mail', width: 30 },
      { header: 'ชื่อ-นามสกุล', key: 'name', width: 30 },
      { header: 'สาขา', key: 'user_group', width: 20 },
      { header: 'คณะ', key: 'branch', width: 20 },
      { header: 'ชื่อกิจกรรมที่เข้าร่วม', key: 'ua_nameactivity', width: 30 },
      
    ];

    // Filter and add rows with data
    const filteredActivities = userActivities.filter(activity => 
      activity.pa_nameactivity === activity.ua_nameactivity && activity.ua_nameactivity === selectedActivity
    );

    filteredActivities.forEach(activity => {
      worksheet.addRow({
        idup: activity.idup,
        mail: activity.mail,
        name: activity.name,
        user_group: activity.user_group,
        branch: activity.branch,
        ua_nameactivity: activity.ua_nameactivity,
        post_id: activity.post_id,
        namegroup: activity.namegroup,
        day_month_year: new Date(activity.day_month_year).toLocaleDateString('th-TH', {
          day: 'numeric',
          month: 'long',
          year: 'numeric',
        }),
        time: activity.time,
        agency: activity.agency,
        details: activity.details,
        type: activity.type,
        importance: activity.importance,
        image: activity.image,
      });
    });

    // Write the file to buffer
    const buffer = await workbook.xlsx.writeBuffer();

    // Send the buffer as a file download
    reply.header('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    reply.header('Content-Disposition', 'attachment; filename=user_activities.xlsx');
    reply.send(buffer);
  } catch (error) {
    console.error('Error generating Excel file:', error);
    reply.code(500).send({ message: 'Internal Server Error' });
  }
});

// Start server
fastify.listen({ port: 3000 }, (err, address) => {
  if (err) {
    fastify.log.error(err);
    process.exit(1);
  }
  fastify.log.info(`Server listening on ${address}`);
});