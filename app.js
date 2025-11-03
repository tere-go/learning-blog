const express = require('express')
const path = require('path')
const { Pool } = require('pg')
const bcrypt = require('bcrypt')
const fs = require('fs')
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const multer = require('multer')
const upload = multer({ storage: multer.memoryStorage() })
const OpenAI = require('openai')
require('dotenv').config()

const app = express()
const port = process.env.PORT || 3000

// Initialize OpenAI client
const openai = process.env.OPENAI_API_KEY ? new OpenAI({ OPENAI_API_KEY: process.env.OPENAI_API_KEY }) : null


// Configure EJS as view engine
app.set('view engine', 'ejs')
app.set('views', path.join(__dirname, 'views'))

// parse cookies and form submissions
app.use(cookieParser())
app.use(express.urlencoded({ extended: false }))
app.use(express.json())

function requireAuthJWT(req, res, next) {
  const token = req.cookies && req.cookies.token
  if (!token) return res.redirect('/login')
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET)
    req.user = payload
    return next()
  } catch {
    const acceptsJson = (req.headers.accept || '').includes('application/json') ||
      (req.headers['content-type'] || '').includes('multipart/form-data') ||
      (req.xhr === true)
    if (acceptsJson) {
      return res.status(401).json({ error: 'auth required' })
    }
    return res.redirect('/login')
  }
}

// connect to the database
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // Neon requires SSL
});

// (moved above) parse cookies + urlencoded

// Explicit route for CSS to ensure correct MIME type (must be before other routes)
app.get('/styles.css', (req, res) => {
  res.setHeader('Content-Type', 'text/css')
  res.sendFile(path.join(__dirname, 'styles.css'))
})

// serve static assets like styles.css (must be before routes)
app.use(express.static(__dirname, {
  setHeaders: (res, path) => {
    if (path.endsWith('.css')) {
      res.setHeader('Content-Type', 'text/css')
    }
  }
}))

app.get('/', (req, res) => {
  res.render('index')
})


//routes
app.get('/materials', requireAuthJWT, async (req, res) => {
  try {
    const userId = req.user && req.user.sub
    const { rows } = await pool.query(
      'SELECT name, basics_done, projects_done, materials_done FROM users_data WHERE id = $1 LIMIT 1',
      [userId]
    )
    const basics = (rows[0]?.basics_done ?? 0) === 1
    const projectsDoneArray = rows[0]?.projects_done || []
    const materialsDoneArray = rows[0]?.materials_done || []
    const projects = Array.isArray(projectsDoneArray) ? projectsDoneArray.length : (typeof projectsDoneArray === 'number' ? projectsDoneArray : 0)
    const materialsCount = Array.isArray(materialsDoneArray) ? materialsDoneArray.length : 0
    const name = rows[0]?.name || 'Your Name'

    // Fetch total counts for progress calculation
    const materialsTotalResult = await pool.query('SELECT COUNT(*) as count FROM materials')
    const materialsTotal = parseInt(materialsTotalResult.rows[0]?.count || 0)

    // Determine tier, instruction, and progress
    let tierText = ''
    let instructionText = ''
    let progressPercent = 0
    let progressLabel = ''
    
    if (!basics) {
      // Rookie tier: haven't finished basics
      tierText = 'Tier: Rookie'
      instructionText = 'Finish basic N8n to level up!'
      if (materialsTotal > 0) {
        progressPercent = Math.round((materialsCount / materialsTotal) * 100)
        progressLabel = `${materialsCount}/${materialsTotal} materials`
      } else {
        progressPercent = 0
        progressLabel = '0 materials completed'
      }
    } else if (projects >= 5) {
      // Superhero tier: finished 5 projects
      tierText = 'Tier: Superhero'
      instructionText = 'Ready to Automate the World!'
      progressPercent = 100
      progressLabel = '5/5 projects completed'
    } else {
      // Hero tier: finished basics but not 5 projects yet
      tierText = 'Tier: Hero'
      const remaining = Math.max(0, 5 - projects)
      instructionText = `Finish ${remaining} more projects to become a Superhero!`
      progressPercent = Math.round((projects / 5) * 100)
      progressLabel = `${projects}/5 projects`
    }

    // Fetch materials and projects for sidebar, sorted alphabetically
    const materialsResult = await pool.query(
      'SELECT id, title FROM materials ORDER BY title ASC'
    )
    const projectsResult = await pool.query(
      'SELECT id, title FROM projects ORDER BY title ASC'
    )
    
    res.render('material', {
      name,
      username: req.user && req.user.username ? `@${req.user.username}` : '@username',
      basics,
      projects,
      tierText,
      instructionText,
      progressPercent,
      progressLabel,
      materialsData: materialsResult.rows || [],
      projectsData: projectsResult.rows || []
    })
  } catch (e) {
    console.error('Materials render error:', e)
    res.status(500).send('Internal server error')
  }
})

// Display individual material
app.get('/material/:id', requireAuthJWT, async (req, res) => {
  try {
    const userId = req.user && req.user.sub
    const { id } = req.params
    
    // Fetch user data for profile
    const { rows } = await pool.query(
      'SELECT name, basics_done, projects_done, materials_done FROM users_data WHERE id = $1 LIMIT 1',
      [userId]
    )
    const basics = (rows[0]?.basics_done ?? 0) === 1
    const projectsDoneArray = rows[0]?.projects_done || []
    const materialsDoneArray = rows[0]?.materials_done || []
    const projects = Array.isArray(projectsDoneArray) ? projectsDoneArray.length : (typeof projectsDoneArray === 'number' ? projectsDoneArray : 0)
    const materialsCount = Array.isArray(materialsDoneArray) ? materialsDoneArray.length : 0
    const name = rows[0]?.name || 'Your Name'
    const materialsDone = rows[0]?.materials_done || []

    // Fetch total counts for progress calculation
    const materialsTotalResult = await pool.query('SELECT COUNT(*) as count FROM materials')
    const materialsTotal = parseInt(materialsTotalResult.rows[0]?.count || 0)

    // Determine tier, instruction, and progress
    let tierText = ''
    let instructionText = ''
    let progressPercent = 0
    let progressLabel = ''
    
    if (!basics) {
      // Rookie tier: haven't finished basics
      tierText = 'Tier: Rookie'
      instructionText = 'Finish basic N8n to level up!'
      if (materialsTotal > 0) {
        progressPercent = Math.round((materialsCount / materialsTotal) * 100)
        progressLabel = `${materialsCount}/${materialsTotal} materials`
      } else {
        progressPercent = 0
        progressLabel = '0 materials completed'
      }
    } else if (projects >= 5) {
      // Superhero tier: finished 5 projects
      tierText = 'Tier: Superhero'
      instructionText = 'Ready to Automate the World!'
      progressPercent = 100
      progressLabel = '5/5 projects completed'
    } else {
      // Hero tier: finished basics but not 5 projects yet
      tierText = 'Tier: Hero'
      const remaining = Math.max(0, 5 - projects)
      instructionText = `Finish ${remaining} more projects to become a Superhero!`
      progressPercent = Math.round((projects / 5) * 100)
      progressLabel = `${projects}/5 projects`
    }

    // Fetch the specific material with both EN and KR content
    const materialResult = await pool.query(
      'SELECT id, writer, title, content_delta, content_delta_kr, quiz_questions, quiz_questions_kr, created_at, updated_at FROM materials WHERE id = $1',
      [id]
    )
    
    if (materialResult.rows.length === 0) {
      return res.status(404).send('Material not found')
    }
    
    const material = materialResult.rows[0]
    
    // Fetch materials and projects for sidebar, sorted alphabetically
    const materialsResult = await pool.query(
      'SELECT id, title FROM materials ORDER BY title ASC'
    )
    const projectsResult = await pool.query(
      'SELECT id, title FROM projects ORDER BY title ASC'
    )
    
    const isCompleted = Array.isArray(materialsDone) && materialsDone.includes(id)
    
    res.render('material-view', {
      name,
      username: req.user && req.user.username ? `@${req.user.username}` : '@username',
      basics,
      projects,
      tierText,
      instructionText,
      progressPercent,
      progressLabel,
      materialsData: materialsResult.rows || [],
      projectsData: projectsResult.rows || [],
      material: {
        id: material.id,
        title: material.title,
        writer: material.writer,
        contentDelta: material.content_delta,
        contentDeltaKr: material.content_delta_kr || null,
        quizQuestions: material.quiz_questions || [],
        quizQuestionsKr: material.quiz_questions_kr || null,
        createdAt: material.created_at,
        updatedAt: material.updated_at,
        isCompleted
      }
    })
  } catch (e) {
    console.error('Material view error:', e)
    res.status(500).send('Internal server error')
  }
})

// Display individual project
app.get('/project/:id', requireAuthJWT, async (req, res) => {
  try {
    const userId = req.user && req.user.sub
    const { id } = req.params
    
    // Fetch user data for profile
    const { rows } = await pool.query(
      'SELECT name, basics_done, projects_done FROM users_data WHERE id = $1 LIMIT 1',
      [userId]
    )
    const basics = (rows[0]?.basics_done ?? 0) === 1
    
    // Block access if basics not finished
    if (!basics) {
      return res.status(403).send('You must complete the basics before accessing projects.')
    }
    
    const projectsDoneArray = rows[0]?.projects_done || []
    const projects = Array.isArray(projectsDoneArray) ? projectsDoneArray.length : (typeof projectsDoneArray === 'number' ? projectsDoneArray : 0)
    const name = rows[0]?.name || 'Your Name'

    // Determine tier, instruction, and progress
    // Note: basics is already checked above, so user is guaranteed to have finished basics
    let tierText = ''
    let instructionText = ''
    let progressPercent = 0
    let progressLabel = ''
    
    if (projects >= 5) {
      // Superhero tier: finished 5 projects
      tierText = 'Tier: Superhero'
      instructionText = 'Ready to Automate the World!'
      progressPercent = 100
      progressLabel = '5/5 projects completed'
    } else {
      // Hero tier: finished basics but not 5 projects yet
      tierText = 'Tier: Hero'
      const remaining = Math.max(0, 5 - projects)
      instructionText = `Finish ${remaining} more projects to become a Superhero!`
      progressPercent = Math.round((projects / 5) * 100)
      progressLabel = `${projects}/5 projects`
    }

    // Fetch the specific project
    const projectResult = await pool.query(
      'SELECT id, writer, title, content_delta, created_at, updated_at FROM projects WHERE id = $1',
      [id]
    )
    
    if (projectResult.rows.length === 0) {
      return res.status(404).send('Project not found')
    }
    
    const project = projectResult.rows[0]
    
    // Fetch materials and projects for sidebar, sorted alphabetically
    const materialsResult = await pool.query(
      'SELECT id, title FROM materials ORDER BY title ASC'
    )
    const projectsResult = await pool.query(
      'SELECT id, title FROM projects ORDER BY title ASC'
    )
    
    const isCompleted = Array.isArray(projectsDoneArray) && projectsDoneArray.includes(id)
    
    res.render('project-view', {
      name,
      username: req.user && req.user.username ? `@${req.user.username}` : '@username',
      basics,
      projects,
      tierText,
      instructionText,
      progressPercent,
      progressLabel,
      materialsData: materialsResult.rows || [],
      projectsData: projectsResult.rows || [],
      project: {
        id: project.id,
        title: project.title,
        writer: project.writer,
        contentDelta: project.content_delta,
        contentDeltaKr: project.content_delta_kr || null,
        createdAt: project.created_at,
        updatedAt: project.updated_at,
        isCompleted
      }
    })
  } catch (e) {
    console.error('Project view error:', e)
    res.status(500).send('Internal server error')
  }
})

// Mark material as complete (quiz passed)
app.post('/material-complete', requireAuthJWT, async (req, res) => {
  try {
    const userId = req.user && req.user.sub
    if (!userId) {
      return res.status(401).json({ error: 'Authentication required' })
    }
    
    const { materialId } = req.body
    if (!materialId) {
      return res.status(400).json({ error: 'Material ID required' })
    }
    
    // Get current materials_done array
    const result = await pool.query(
      'SELECT materials_done, basics_done FROM users_data WHERE id = $1',
      [userId]
    )
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' })
    }
    
    let materialsDone = result.rows[0].materials_done || []
    let basicsDone = result.rows[0].basics_done ?? 0
    let shouldUpdateBasics = false
    
    // If materialId is not already in the array, add it
    if (!materialsDone.includes(materialId)) {
      materialsDone.push(materialId)
      
      // Check if all materials are completed
      const allMaterialsResult = await pool.query('SELECT id FROM materials')
      const allMaterialIds = allMaterialsResult.rows.map(row => String(row.id)) // Ensure strings
      const totalMaterials = allMaterialIds.length
      
      // Ensure materialsDone contains strings for comparison
      const materialsDoneStrings = materialsDone.map(id => String(id))
      
      // Check if all material IDs are in the materialsDone array
      const allCompleted = totalMaterials > 0 && allMaterialIds.every(id => materialsDoneStrings.includes(id))
      
      console.log(`[Material Complete] User ${userId}: materialsDone=${materialsDoneStrings.length}, totalMaterials=${totalMaterials}, allCompleted=${allCompleted}, basicsDone=${basicsDone}`)
      
      // If all materials are done and basics_done is not set, set it to 1
      if (allCompleted && basicsDone !== 1) {
        basicsDone = 1
        shouldUpdateBasics = true
        console.log(`[Material Complete] Setting basics_done = 1 for user ${userId}`)
      }
      
      // Update database
      if (shouldUpdateBasics) {
        await pool.query(
          'UPDATE users_data SET materials_done = $1, basics_done = $2, updated_at = now() WHERE id = $3',
          [JSON.stringify(materialsDone), basicsDone, userId]
        )
      } else {
        await pool.query(
          'UPDATE users_data SET materials_done = $1, updated_at = now() WHERE id = $2',
          [JSON.stringify(materialsDone), userId]
        )
      }
    }
    
    return res.status(200).json({ 
      ok: true, 
      message: 'Material marked as complete',
      basicsDone: shouldUpdateBasics ? 1 : basicsDone
    })
  } catch (e) {
    console.error('Material complete error:', e)
    return res.status(500).json({ error: 'Server error', detail: e.message })
  }
})

// Mark project as complete
app.post('/project-complete', requireAuthJWT, async (req, res) => {
  try {
    const userId = req.user && req.user.sub
    if (!userId) {
      return res.status(401).json({ error: 'Authentication required' })
    }
    
    const { projectId } = req.body
    if (!projectId) {
      return res.status(400).json({ error: 'Project ID required' })
    }
    
    // Get current projects_done array
    const result = await pool.query(
      'SELECT projects_done FROM users_data WHERE id = $1',
      [userId]
    )
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' })
    }
    
    let projectsDone = result.rows[0].projects_done || []
    
    // Handle both array and number types
    if (typeof projectsDone === 'number') {
      projectsDone = []
    }
    if (!Array.isArray(projectsDone)) {
      projectsDone = []
    }
    
    // If projectId is not already in the array, add it
    if (!projectsDone.includes(projectId)) {
      projectsDone.push(projectId)
      
      // Update database
      await pool.query(
        'UPDATE users_data SET projects_done = $1, updated_at = now() WHERE id = $2',
        [JSON.stringify(projectsDone), userId]
      )
    }
    
    return res.status(200).json({ 
      ok: true, 
      message: 'Project marked as complete' 
    })
  } catch (e) {
    console.error('Project complete error:', e)
    return res.status(500).json({ error: 'Server error', detail: e.message })
  }
})

app.get('/signup', (req, res) => {
  res.render('signup')
})

app.get('/login', (req, res) => {
  res.render('login')
})

// post editor page
app.get('/material-editor', requireAuthJWT, (req, res) => {
  // Only allow terego or admin
  const username = req.user && req.user.username
  if (!username || (username !== 'terego' && username !== 'admin')) {
    return res.status(403).send('Access denied. Only terego and admin can access this page.')
  }
  res.render('material-editor')
})

// project editor page
app.get('/project-editor', requireAuthJWT, (req, res) => {
  // Only allow terego or admin
  const username = req.user && req.user.username
  if (!username || (username !== 'terego' && username !== 'admin')) {
    return res.status(403).send('Access denied. Only terego and admin can access this page.')
  }
  res.render('project-editor')
})

// admin dashboard
app.get('/admin-dashboard', requireAuthJWT, async (req, res) => {
  try {
    // Only allow terego or admin
    const username = req.user && req.user.username
    if (!username || (username !== 'terego' && username !== 'admin')) {
      return res.status(403).send('Access denied. Only terego and admin can access this page.')
    }
    
    // Fetch materials and projects
    const materialsResult = await pool.query(
      'SELECT id, writer, title, created_at, updated_at FROM materials ORDER BY created_at DESC'
    )
    const projectsResult = await pool.query(
      'SELECT id, writer, title, created_at, updated_at FROM projects ORDER BY created_at DESC'
    )
    
    res.render('admin-dashboard', {
      materials: materialsResult.rows || [],
      projects: projectsResult.rows || []
    })
  } catch (e) {
    console.error('Admin dashboard error:', e)
    res.status(500).send('Internal server error')
  }
})

app.post('/logout', (req, res) => {
  res.clearCookie('token', { httpOnly: true, sameSite: 'lax', secure: false })
  return res.redirect('/login')
})

// upload endpoint using ImageKit: returns { url }
// Requires env: IMAGEKIT_PRIVATE_KEY, IMAGEKIT_PUBLIC_KEY (optional here), IMAGEKIT_URL_ENDPOINT
app.post('/upload', requireAuthJWT, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'file required' })
    const { IMAGEKIT_PRIVATE_KEY, IMAGEKIT_URL_ENDPOINT } = process.env
    if (!IMAGEKIT_PRIVATE_KEY || !IMAGEKIT_URL_ENDPOINT) {
      return res.status(500).json({ error: 'missing IMAGEKIT env vars' })
    }

    const base64 = req.file.buffer.toString('base64')
    const fileName = req.file.originalname || `upload-${Date.now()}`

    const form = new FormData()
    form.append('file', base64)
    form.append('fileName', fileName)

    const auth = Buffer.from(`${IMAGEKIT_PRIVATE_KEY}:`).toString('base64')
    const response = await fetch('https://upload.imagekit.io/api/v1/files/upload', {
      method: 'POST',
      headers: { Authorization: `Basic ${auth}` },
      body: form
    })
    if (!response.ok) {
      const text = await response.text().catch(() => '')
      console.error('ImageKit upload failed:', response.status, text)
      return res.status(502).json({ error: 'upload failed', detail: text })
    }
    const data = await response.json()
    const url = (data && data.url) || (IMAGEKIT_URL_ENDPOINT && data && data.filePath ? `${IMAGEKIT_URL_ENDPOINT}${data.filePath}` : null)
    if (!url) return res.status(500).json({ error: 'invalid response from imagekit' })
    return res.json({ url })
  } catch (e) {
    console.error('Upload error:', e)
    return res.status(500).json({ error: 'server error' })
  }
})

// save material
app.post('/material-editor', requireAuthJWT, async (req, res) => {
  try {
    const username = req.user && req.user.username
    if (!username) return res.status(401).json({ error: 'authentication required' })
    
    // Only allow terego or admin to save materials
    if (username !== 'terego' && username !== 'admin') {
      return res.status(403).json({ error: 'Only admins can save materials' })
    }
    
    const { title, contentDelta, quizQuestions } = req.body || {}
    if (!title || !contentDelta) return res.status(400).json({ error: 'title and content required' })
    
    // Validate and sanitize quiz questions
    const validQuizQuestions = Array.isArray(quizQuestions) ? quizQuestions.filter(q => 
      q && q.question && Array.isArray(q.options) && q.options.length >= 2 && 
      typeof q.correctAnswer === 'number' && q.correctAnswer >= 0 && q.correctAnswer < q.options.length
    ) : []
    
    // Convert to JSON strings for JSONB columns
    // Explicitly generate UUID to ensure it's set
    // writer is now the username (TEXT) instead of user ID
    
    // Translate content to Korean using OpenAI if available
    let contentDeltaKorean = null
    let quizQuestionsKorean = null
    
    if (openai) {
      try {
        const contentDeltaText = JSON.stringify(contentDelta)
        const response = await openai.chat.completions.create({
          model: "gpt-4o-mini",
          messages: [
            {
              role: 'user',
              content: `Translate the following JSON content into Korean, keeping the JSON structure intact: ${contentDeltaText}`
            }
          ],
          max_tokens: 2000
        })
        
        const translatedText = response.choices[0]?.message?.content || null
        if (translatedText) {
          try {
            contentDeltaKorean = JSON.parse(translatedText)
          } catch {
            // If parsing fails, try to extract JSON from the response
            const jsonMatch = translatedText.match(/\{[\s\S]*\}/)
            if (jsonMatch) {
              contentDeltaKorean = JSON.parse(jsonMatch[0])
            }
          }
        }
        console.log('Material translation successful:', contentDeltaKorean ? 'Yes' : 'No')
      } catch (error) {
        console.error('Material translation error:', error.message)
        // Continue without translation if OpenAI fails
      }
      
      // Translate quiz questions to Korean
      if (validQuizQuestions.length > 0) {
        try {
          const quizQuestionsText = JSON.stringify(validQuizQuestions)
          const quizResponse = await openai.chat.completions.create({
            model: "gpt-4o-mini",
            messages: [
              {
                role: 'user',
                content: `Translate the following quiz questions array into Korean. Keep the exact JSON structure with "question", "options" array, and "correctAnswer" index. Only translate the text content, keep the structure and correctAnswer index unchanged: ${quizQuestionsText}`
              }
            ],
            max_tokens: 1000
          })
          
          const translatedQuizText = quizResponse.choices[0]?.message?.content || null
          if (translatedQuizText) {
            try {
              quizQuestionsKorean = JSON.parse(translatedQuizText)
            } catch {
              // If parsing fails, try to extract JSON array from the response
              const jsonMatch = translatedQuizText.match(/\[[\s\S]*\]/)
              if (jsonMatch) {
                quizQuestionsKorean = JSON.parse(jsonMatch[0])
              }
            }
          }
          console.log('Quiz questions translation successful:', quizQuestionsKorean ? 'Yes' : 'No')
        } catch (error) {
          console.error('Quiz questions translation error:', error.message)
          // Continue without translation if OpenAI fails
        }
      }
    }

    const result = await pool.query(
      `INSERT INTO materials (id, writer, title, content_delta, content_delta_kr, quiz_questions, quiz_questions_kr)
       VALUES (gen_random_uuid(), $1, $2, $3::jsonb, $4::jsonb, $5::jsonb, $6::jsonb)
       RETURNING id`,
      [
        username, 
        title, 
        JSON.stringify(contentDelta), 
        contentDeltaKorean ? JSON.stringify(contentDeltaKorean) : null,
        JSON.stringify(validQuizQuestions),
        quizQuestionsKorean ? JSON.stringify(quizQuestionsKorean) : null
      ]
    )
    
    return res.status(201).json({ 
      ok: true, 
      id: result.rows[0]?.id,
      message: 'Material saved successfully' 
    })
  } catch (e) {
    console.error('Save material error:', e)
    console.error('Error code:', e.code)
    console.error('Error message:', e.message)
    console.error('Error detail:', e.detail)
    
    if (e.code === '23503') {
      return res.status(400).json({ error: 'invalid writer ID' })
    }
    if (e.code === '42P01') {
      return res.status(500).json({ error: 'materials table does not exist - check database schema' })
    }
    return res.status(500).json({ error: 'server error', detail: e.message, code: e.code })
  }
})

// save project
app.post('/project-editor', requireAuthJWT, async (req, res) => {
  try {
    const username = req.user && req.user.username
    if (!username) return res.status(401).json({ error: 'authentication required' })
    
    // Only allow terego or admin to save projects
    if (username !== 'terego' && username !== 'admin') {
      return res.status(403).json({ error: 'Only terego and admin can save projects' })
    }
    
    const { title, contentDelta } = req.body || {}
    if (!title || !contentDelta) return res.status(400).json({ error: 'title and content required' })
    
    // Convert to JSON strings for JSONB columns
    // Explicitly generate UUID and timestamps to ensure they're set
    // writer is the username (TEXT)
    
    // Translate content to Korean using OpenAI if available
    let contentDeltaKorean = null
    if (openai) {
      try {
        const contentDeltaText = JSON.stringify(contentDelta)
        const response = await openai.chat.completions.create({
          model: "gpt-4o-mini",
          messages: [
            {
              role: 'user',
              content: `Translate the following JSON content into Korean, keeping the JSON structure intact: ${contentDeltaText}`
            }
          ],
          max_tokens: 2000
        })
        
        const translatedText = response.choices[0]?.message?.content || null
        if (translatedText) {
          try {
            contentDeltaKorean = JSON.parse(translatedText)
          } catch {
            // If parsing fails, try to extract JSON from the response
            const jsonMatch = translatedText.match(/\{[\s\S]*\}/)
            if (jsonMatch) {
              contentDeltaKorean = JSON.parse(jsonMatch[0])
            }
          }
        }
        console.log('Translation successful:', contentDeltaKorean ? 'Yes' : 'No')
      } catch (error) {
        console.error('Translation error:', error.message)
        // Continue without translation if OpenAI fails
      }
    }
    
    const result = await pool.query(
      `INSERT INTO projects (id, writer, title, content_delta, content_delta_kr, created_at, updated_at)
       VALUES (gen_random_uuid(), $1, $2, $3::jsonb, $4::jsonb, now(), now())
       RETURNING id`,
      [username, title, JSON.stringify(contentDelta), contentDeltaKorean ? JSON.stringify(contentDeltaKorean) : null]
    )
    
    return res.status(201).json({ 
      ok: true, 
      id: result.rows[0]?.id,
      message: 'Project saved successfully' 
    })
  } catch (e) {
    console.error('Save project error:', e)
    console.error('Error code:', e.code)
    console.error('Error message:', e.message)
    console.error('Error detail:', e.detail)
    
    if (e.code === '42P01') {
      return res.status(500).json({ error: 'projects table does not exist - check database schema' })
    }
    return res.status(500).json({ error: 'server error', detail: e.message, code: e.code })
  }
})

// delete material
app.delete('/material-delete/:id', requireAuthJWT, async (req, res) => {
  try {
    const username = req.user && req.user.username
    if (!username || (username !== 'terego' && username !== 'admin')) {
      return res.status(403).json({ error: 'Only terego and admin can delete materials' })
    }
    
    const { id } = req.params
    const result = await pool.query('DELETE FROM materials WHERE id = $1 RETURNING id', [id])
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Material not found' })
    }
    
    return res.status(200).json({ ok: true, message: 'Material deleted successfully' })
  } catch (e) {
    console.error('Delete material error:', e)
    return res.status(500).json({ error: 'server error', detail: e.message })
  }
})

// delete project
app.delete('/project-delete/:id', requireAuthJWT, async (req, res) => {
  try {
    const username = req.user && req.user.username
    if (!username || (username !== 'terego' && username !== 'admin')) {
      return res.status(403).json({ error: 'Only terego and admin can delete projects' })
    }
    
    const { id } = req.params
    const result = await pool.query('DELETE FROM projects WHERE id = $1 RETURNING id', [id])
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Project not found' })
    }
    
    return res.status(200).json({ ok: true, message: 'Project deleted successfully' })
  } catch (e) {
    console.error('Delete project error:', e)
    return res.status(500).json({ error: 'server error', detail: e.message })
  }
})

// ensure users table exists
async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users_data (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `)
  // add progress columns if missing
  await pool.query('ALTER TABLE users_data ADD COLUMN IF NOT EXISTS basics_done INTEGER NOT NULL DEFAULT 0')
  await pool.query('ALTER TABLE users_data ADD COLUMN IF NOT EXISTS projects_done INTEGER NOT NULL DEFAULT 0')
  await pool.query('ALTER TABLE users_data ADD COLUMN IF NOT EXISTS materials_done JSONB NOT NULL DEFAULT \'[]\'::jsonb')
  
  // Migrate projects_done from INTEGER to JSONB array if needed
  const projectsDoneCol = await pool.query(`
    SELECT data_type FROM information_schema.columns 
    WHERE table_name = 'users_data' AND column_name = 'projects_done'
  `).then(r => r.rows[0]?.data_type).catch(() => null)
  
  if (projectsDoneCol === 'integer') {
    // Add new JSONB column if it doesn't exist
    await pool.query('ALTER TABLE users_data ADD COLUMN IF NOT EXISTS projects_done_jsonb JSONB DEFAULT \'[]\'::jsonb')
    // Migrate: keep integer value for now, will be converted gradually as projects are marked done
    await pool.query(`UPDATE users_data SET projects_done_jsonb = '[]'::jsonb WHERE projects_done_jsonb IS NULL`)
    // Drop old column and rename new one
    await pool.query('ALTER TABLE users_data DROP COLUMN IF EXISTS projects_done')
    await pool.query('ALTER TABLE users_data RENAME COLUMN projects_done_jsonb TO projects_done')
    await pool.query('ALTER TABLE users_data ALTER COLUMN projects_done SET DEFAULT \'[]\'::jsonb')
    await pool.query('ALTER TABLE users_data ALTER COLUMN projects_done SET NOT NULL')
  }
  
  // Ensure projects_done is JSONB with default
  await pool.query('ALTER TABLE users_data ADD COLUMN IF NOT EXISTS projects_done JSONB NOT NULL DEFAULT \'[]\'::jsonb')
  // Ensure pgcrypto extension exists before creating materials table
  await pool.query('CREATE EXTENSION IF NOT EXISTS pgcrypto')
  
  // Check if materials table exists and migrate writer column if needed
  const tableExists = await pool.query(`
    SELECT EXISTS (
      SELECT FROM information_schema.tables 
      WHERE table_name = 'materials'
    )
  `).then(r => r.rows[0]?.exists)
  
  if (tableExists) {
    // Check if writer is INTEGER, if so migrate to TEXT
    const colType = await pool.query(`
      SELECT data_type FROM information_schema.columns 
      WHERE table_name = 'materials' AND column_name = 'writer'
    `).then(r => r.rows[0]?.data_type).catch(() => null)
    
    if (colType === 'integer') {
      // Drop foreign key constraint if exists, then change type
      await pool.query(`
        ALTER TABLE materials 
        DROP CONSTRAINT IF EXISTS materials_writer_fkey
      `).catch(() => {})
      await pool.query(`
        ALTER TABLE materials 
        ALTER COLUMN writer TYPE TEXT USING writer::TEXT
      `).catch(() => {})
    }
  } else {
    // Create table with TEXT writer (username)
    await pool.query(`
      CREATE TABLE materials (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        writer TEXT NOT NULL,
        title TEXT NOT NULL,
        content_delta JSONB NOT NULL,
        content_delta_kr JSONB,
        quiz_questions JSONB NOT NULL DEFAULT '[]'::jsonb,
        quiz_questions_kr JSONB,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `)
  }
  
  // Add content_delta_kr column to materials if it doesn't exist
  await pool.query('ALTER TABLE materials ADD COLUMN IF NOT EXISTS content_delta_kr JSONB')
  // Add quiz_questions_kr column to materials if it doesn't exist
  await pool.query('ALTER TABLE materials ADD COLUMN IF NOT EXISTS quiz_questions_kr JSONB')
  
  // If table exists but missing default, add it
  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'materials' 
        AND column_name = 'id' 
        AND column_default IS NOT NULL
      ) THEN
        ALTER TABLE materials ALTER COLUMN id SET DEFAULT gen_random_uuid();
      END IF;
    END $$;
  `).catch(() => {}) // Ignore errors if column doesn't exist
  
  // Create projects table (similar to materials but without quiz_questions)
  const projectsTableExists = await pool.query(`
    SELECT EXISTS (
      SELECT FROM information_schema.tables 
      WHERE table_name = 'projects'
    )
  `).then(r => r.rows[0]?.exists)
  
  if (!projectsTableExists) {
    await pool.query(`
      CREATE TABLE projects (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        writer TEXT NOT NULL,
        title TEXT NOT NULL,
        content_delta JSONB NOT NULL,
        content_delta_kr JSONB,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `)
  }
  
  // Add content_delta_kr column to projects if it doesn't exist
  await pool.query('ALTER TABLE projects ADD COLUMN IF NOT EXISTS content_delta_kr JSONB')
  
  // Ensure projects table has UUID default
  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'projects' 
        AND column_name = 'id' 
        AND column_default IS NOT NULL
      ) THEN
        ALTER TABLE projects ALTER COLUMN id SET DEFAULT gen_random_uuid();
      END IF;
    END $$;
  `).catch(() => {}) // Ignore errors if column doesn't exist
}
ensureSchema().catch(err => {
  console.error('Failed to ensure schema:', err)
})

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

function renderSignupWithError(res, message, status = 400) {
  try {
    res.status(status).render('signup', { error: message })
  } catch (e) {
    res.status(status).send(message)
  }
}

function renderLoginWithError(res, message, status = 401) {
  try {
    res.status(status).render('login', { error: message })
  } catch (e) {
    res.status(status).send(message)
  }
}

// handle signup form
app.post('/signup', async (req, res) => {
  const { name, username, email, password } = req.body || {}
  if (!name || !username || !email || !password) {
    return renderSignupWithError(res, 'Name, username, email, and password are required', 400)
  }
  try {
    const passwordHash = await bcrypt.hash(password, 10)
    await pool.query(
      'INSERT INTO users_data (name, username, password_hash, email) VALUES ($1, $2, $3, $4)',
      [name, username, passwordHash, email]
    )
    return res.redirect('/login')
  } catch (err) {
    if (err && err.code === '23505') {
      // unique_violation on username
      return renderSignupWithError(res, 'Username or email already exists', 409)
    }
    console.error('Signup error:', err)
    return renderSignupWithError(res, 'Internal server error', 500)
  }
})

// handle login form (username OR email + password)
app.post('/login', async (req, res) => {
  const { username, password } = req.body || {}
  if (!username || !password) {
    return renderLoginWithError(res, 'Username/email and password are required', 400)
  }
  try {
    const { rows } = await pool.query(
      'SELECT id, username, email, password_hash FROM users_data WHERE username = $1 OR email = $1 LIMIT 1',
      [username]
    )
    if (!rows.length) {
      return renderLoginWithError(res, 'Incorrect Username/Email', 401)
    }
    const user = rows[0]
    const ok = await bcrypt.compare(password, user.password_hash)
    if (!ok) {
      return renderLoginWithError(res, 'Incorrect Password', 401)
    }
    const token = jwt.sign(
      { sub: user.id, username: user.username, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    )
    res.cookie('token', token, {
      httpOnly: true,
      sameSite: 'lax',
      secure: false,
      maxAge: 1000 * 60 * 60 * 24 * 7
    })
    return res.redirect('/materials')
  } catch (err) {
    console.error('Login error:', err)
    return renderLoginWithError(res, 'Internal server error', 500)
  }
})

const server = app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})

// Export for Vercel serverless
module.exports = app

app.get('/users', async (req, res) => {
  const result = await pool.query('SELECT * FROM neon_auth.users');
  res.json(result.rows);
});
