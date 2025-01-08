const express = require('express')
const mongoose = require('mongoose')
const bodyParser = require('body-parser')
const multer = require('multer')
const csv = require('csv-parser')
const fs = require('fs')
const path = require('path')
const session = require('express-session')
const PDFDocument = require('pdfkit')
const bcrypt = require('bcrypt')

const app = express()
const port = 3000

// Multer setup for file uploads
const upload = multer({ dest: 'uploads/' })

// Middleware
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))
app.use(express.static('public'))
app.use(
	session({
		secret: 'secret',
		resave: false,
		saveUninitialized: true,
	})
)

// Set EJS as templating engine
app.set('view engine', 'ejs')

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/medticket2')

const db = mongoose.connection
db.on('error', console.error.bind(console, 'connection error:'))
db.once('open', () => {
	console.log('Connected to MongoDB')
})

// Ticket model
const ticketSchema = new mongoose.Schema({
	name: String,
	internal_number: String,
	department: String,
	title: String,
	description: String,
	section: String,
	category: String,
	priority: { type: String, enum: ['low', 'medium', 'high'], default: 'medium' },
	recurrence: { type: String, enum: ['once', 'recurring'], default: 'once' },
	status: { type: String, default: 'open' },
	assigned_to: String,
	comments: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Comment' }],
	created_at: { type: Date, default: Date.now },
})

const Ticket = mongoose.model('Ticket', ticketSchema)

// Comment model
const commentSchema = new mongoose.Schema({
	ticket: { type: mongoose.Schema.Types.ObjectId, ref: 'Ticket' },
	user: String,
	content: String,
	created_at: { type: Date, default: Date.now },
	updated_at: { type: Date, default: Date.now },
})

const Comment = mongoose.model('Comment', commentSchema)

// Department model
const departmentSchema = new mongoose.Schema({
	internal_number: String,
	department: String,
	file: String, // Dodajemy pole do przechowywania nazwy pliku
})

const Department = mongoose.model('Department', departmentSchema)

// Category model
const categorySchema = new mongoose.Schema({
	section: String,
	category: String,
	file: String, // Dodajemy pole do przechowywania nazwy pliku
})

const Category = mongoose.model('Category', categorySchema)

// User model
const userSchema = new mongoose.Schema({
	firstName: String,
	lastName: String,
	username: String,
	password: String,
	permissions: [String], // Dodajemy pole do przechowywania uprawnień
	avatar: String, // Dodajemy pole do przechowywania awatara
})

const User = mongoose.model('User', userSchema)

// History model
const historySchema = new mongoose.Schema({
	filename: String,
	date: { type: Date, default: Date.now },
})

const History = mongoose.model('History', historySchema)

// Middleware to set a test user session
app.use((req, res, next) => {
	if (!req.session.user) {
		req.session.user = { username: 'testuser' }
	}
	next()
})

// Middleware to check if user is logged in
function checkAuth(req, res, next) {
	if (!req.session.user) {
		return res.redirect('/login-required')
	}
	next()
}

// Middleware to handle errors
app.use((err, req, res, next) => {
	console.error(err.stack)
	res.status(500).send('Coś poszło nie tak!')
})

// Routes
app.get('/', async (req, res) => {
	const departments = await Department.find()
	const categories = await Category.find()
	res.render('index', { departments, categories })
})

app.get('/sections', async (req, res) => {
	const categories = await Category.find()
	const sections = [...new Set(categories.map(cat => cat.section))]
	res.render('sections', { sections })
})

app.post('/tickets', async (req, res) => {
	const ticket = new Ticket(req.body)
	await ticket.save()
	res.redirect(`/thank-you?id=${ticket._id}`)
})

app.get('/thank-you', (req, res) => {
	const ticketId = req.query.id
	res.render('thank-you', { ticketId })
})

app.get('/tickets', async (req, res) => {
	const tickets = await Ticket.find()
	res.render('tickets', { tickets })
})

app.get('/tickets/:id', async (req, res) => {
	const ticket = await Ticket.findById(req.params.id).populate('comments')
	const users = await User.find({ permissions: ticket.section })
	res.render('ticket', { ticket, users, currentUser: req.session.user.username })
})

app.post('/tickets/:id/assign', async (req, res) => {
	const ticket = await Ticket.findByIdAndUpdate(req.params.id, { assigned_to: req.body.assigned_to }, { new: true })
	res.redirect(`/tickets/${ticket._id}`)
})

app.post('/tickets/:id/comments', async (req, res) => {
	const comment = new Comment({
		ticket: req.params.id,
		user: req.body.user,
		content: req.body.content,
	})
	await comment.save()
	await Ticket.findByIdAndUpdate(req.params.id, { $push: { comments: comment._id } })
	res.redirect(`/tickets/${req.params.id}`)
})

app.put('/comments/:id', async (req, res) => {
	const comment = await Comment.findByIdAndUpdate(
		req.params.id,
		{ content: req.body.content, updated_at: Date.now() },
		{ new: true }
	)
	res.json(comment)
})

app.delete('/comments/:id', async (req, res) => {
	const comment = await Comment.findByIdAndDelete(req.params.id)
	await Ticket.findByIdAndUpdate(comment.ticket, { $pull: { comments: comment._id } })
	res.json({ message: 'Comment deleted' })
})

app.get('/section/:section', async (req, res) => {
	const section = req.params.section
	const tickets = await Ticket.find({ section })
	res.render('section', { section, tickets })
})

app.put('/tickets/:id', async (req, res) => {
	const ticket = await Ticket.findByIdAndUpdate(req.params.id, req.body, { new: true })
	res.json(ticket)
})

app.delete('/tickets/:id', async (req, res) => {
	await Ticket.findByIdAndDelete(req.params.id)
	res.json({ message: 'Ticket deleted' })
})

// Route to generate ticket PDF
app.get('/tickets/:id/pdf', async (req, res) => {
	const ticket = await Ticket.findById(req.params.id).populate('comments')
	const doc = new PDFDocument()
	doc.font('Helvetica') // Ustawienie czcionki obsługującej polskie znaki
	res.setHeader('Content-Type', 'application/pdf')
	res.setHeader('Content-Disposition', `attachment; filename=ticket_${ticket._id}.pdf`)
	doc.pipe(res)
	doc.fontSize(20).text(`Zgłoszenie: ${ticket.title}`, { align: 'center' })
	doc.moveDown()
	doc.fontSize(14).text(`Imię zgłaszającego: ${ticket.name}`)
	doc.text(`Numer wewnętrzny: ${ticket.internal_number}`)
	doc.text(`Dział: ${ticket.department}`)
	doc.text(`Sekcja: ${ticket.section}`)
	doc.text(`Kategoria: ${ticket.category}`)
	doc.text(`Priorytet: ${ticket.priority}`)
	doc.text(`Powtarzalność: ${ticket.recurrence}`)
	doc.text(`Status: ${ticket.status}`)
	doc.text(`Pracownik przypisany: ${ticket.assigned_to || 'Nie przypisano'}`)
	doc.text(`Data utworzenia: ${ticket.created_at.toLocaleString()}`)
	doc.moveDown()
	doc.fontSize(16).text('Opis:')
	doc.fontSize(14).text(ticket.description)
	doc.moveDown()
	doc.fontSize(16).text('Komentarze:')
	ticket.comments.forEach(comment => {
		doc.fontSize(14).text(`- ${comment.user} (${new Date(comment.created_at).toLocaleString()}): ${comment.content}`)
	})
	doc.end()
})

// Route to generate report PDF for a specific ticket
app.get('/tickets/:id/report/pdf', async (req, res) => {
	const ticket = await Ticket.findById(req.params.id).populate('comments')
	const doc = new PDFDocument()
	doc.font('Helvetica') // Ustawienie czcionki obsługującej polskie znaki
	res.setHeader('Content-Type', 'application/pdf')
	res.setHeader('Content-Disposition', `attachment; filename=report_${ticket._id}.pdf`)
	doc.pipe(res)
	doc.fontSize(20).text('Raport zgłoszenia', { align: 'center' })
	doc.moveDown()
	doc.fontSize(16).text(`Zgłoszenie: ${ticket.title}`)
	doc.fontSize(14).text(`Imię zgłaszającego: ${ticket.name}`)
	doc.text(`Numer wewnętrzny: ${ticket.internal_number}`)
	doc.text(`Dział: ${ticket.department}`)
	doc.text(`Sekcja: ${ticket.section}`)
	doc.text(`Kategoria: ${ticket.category}`)
	doc.text(`Priorytet: ${ticket.priority}`)
	doc.text(`Powtarzalność: ${ticket.recurrence}`)
	doc.text(`Status: ${ticket.status}`)
	doc.text(`Pracownik przypisany: ${ticket.assigned_to || 'Nie przypisano'}`)
	doc.text(`Data utworzenia: ${ticket.created_at.toLocaleString()}`)
	doc.moveDown()
	doc.fontSize(16).text('Opis:')
	doc.fontSize(14).text(ticket.description)
	doc.moveDown()
	doc.fontSize(16).text('Komentarze:')
	ticket.comments.forEach(comment => {
		doc.fontSize(14).text(`- ${comment.user} (${new Date(comment.created_at).toLocaleString()}): ${comment.content}`)
	})
	doc.end()
})

// Trasa logowania
app.get('/login', (req, res) => {
	res.render('login')
})

app.post('/login', async (req, res) => {
	const { username, password } = req.body
	const user = await User.findOne({ username })

	if (!user) {
		return res.status(400).send('Nieprawidłowa nazwa użytkownika lub hasło')
	}

	const isMatch = await bcrypt.compare(password, user.password)

	if (!isMatch) {
		return res.status(400).send('Nieprawidłowa nazwa użytkownika lub hasło')
	}

	req.session.user = user
	res.redirect('/')
})

// Admin routes
app.get('/admin', (req, res) => {
	res.render('admin')
})

app.get('/admin/import-contacts', async (req, res) => {
	fs.readdir('uploads', async (err, files) => {
		if (err) {
			console.error(err)
			res.status(500).send('Error reading files')
		} else {
			const contactsFiles = files.filter(file => file.startsWith('contacts'))
			const categoriesFiles = files.filter(file => file.startsWith('categories'))
			const history = await History.find().sort({ date: -1 })
			res.render('import-contacts', { files: { contacts: contactsFiles, categories: categoriesFiles }, history })
		}
	})
})

app.post('/admin/upload', upload.single('file'), (req, res) => {
	const results = []
	fs.createReadStream(req.file.path)
		.pipe(csv())
		.on('data', data => {
			data.file = req.file.filename // Dodajemy nazwę pliku do każdego rekordu
			results.push(data)
		})
		.on('end', async () => {
			await Department.deleteMany({}) // Usuń wszystkie istniejące rekordy
			await Department.insertMany(results)
			await new History({ filename: req.file.filename }).save()
			res.redirect('/admin/import-contacts')
		})
})

app.post('/admin/upload-categories', upload.single('file'), (req, res) => {
	const results = []
	fs.createReadStream(req.file.path)
		.pipe(csv())
		.on('data', data => {
			data.file = req.file.filename // Dodajemy nazwę pliku do każdego rekordu
			results.push(data)
		})
		.on('end', async () => {
			await Category.deleteMany({}) // Usuń wszystkie istniejące rekordy
			await Category.insertMany(results)
			await new History({ filename: req.file.filename }).save()
			res.redirect('/admin/import-contacts')
		})
})

app.post('/admin/delete', async (req, res) => {
	const filePath = path.join(__dirname, 'uploads', req.body.filename)
	fs.unlink(filePath, async err => {
		if (err) {
			console.error(err)
			res.status(500).send('Error deleting file')
		} else {
			// Usuń odpowiednie rekordy z kolekcji Department
			await Department.deleteMany({ file: req.body.filename })
			res.redirect('/admin/import-contacts')
		}
	})
})

app.post('/admin/delete-categories', async (req, res) => {
	const filePath = path.join(__dirname, 'uploads', req.body.filename)
	fs.unlink(filePath, async err => {
		if (err) {
			console.error(err)
			res.status(500).send('Error deleting file')
		} else {
			// Usuń odpowiednie rekordy z kolekcji Category
			await Category.deleteMany({ file: req.body.filename })
			res.redirect('/admin/import-contacts')
		}
	})
})

app.get('/admin/add-user', (req, res) => {
	res.render('add-user', { error: null })
})

app.post('/admin/add-user', async (req, res) => {
	const { firstName, lastName, username, password, confirmPassword, permissions } = req.body

	if (password !== confirmPassword) {
		return res.render('add-user', { error: 'Hasła nie są zgodne' })
	}

	try {
		const hashedPassword = await bcrypt.hash(password, 10)
		const user = new User({
			firstName,
			lastName,
			username,
			password: hashedPassword,
			permissions: Array.isArray(permissions) ? permissions : [permissions],
		})
		await user.save()
		res.redirect('/admin/manage-users')
	} catch (error) {
		res.render('add-user', { error: 'Wystąpił błąd podczas dodawania użytkownika' })
	}
})

app.get('/admin/manage-users', async (req, res) => {
	const users = await User.find()
	res.render('manage-users', { users })
})

app.post('/admin/delete-user', async (req, res) => {
	await User.findByIdAndDelete(req.body.userId)
	res.redirect('/admin/manage-users')
})

app.post('/admin/add-permission', async (req, res) => {
	await User.findByIdAndUpdate(req.body.userId, { $addToSet: { permissions: req.body.permission } })
	res.redirect('/admin/manage-users')
})

app.post('/admin/remove-permission', async (req, res) => {
	await User.findByIdAndUpdate(req.body.userId, { $pull: { permissions: req.body.permission } })
	res.redirect('/admin/manage-users')
})
app.get('/user-panel', checkAuth, async (req, res, next) => {
	try {
		const user = await User.findById(req.session.user._id)
		if (!user) {
			return res.redirect('/login')
		}
		const ticketsInProgress = await Ticket.find({ assigned_to: user.username, status: 'open' })
		const ticketsCompleted = await Ticket.find({ assigned_to: user.username, status: 'closed' })
		res.render('user-panel', { user, ticketsInProgress, ticketsCompleted, error: null })
	} catch (err) {
		next(err)
	}
})

app.post('/user-panel/change-password', checkAuth, async (req, res, next) => {
	try {
		const { currentPassword, newPassword, confirmPassword } = req.body
		const user = await User.findById(req.session.user._id)
		if (!user) {
			return res.redirect('/login')
		}

		const isMatch = await bcrypt.compare(currentPassword, user.password)
		const ticketsInProgress = await Ticket.find({ assigned_to: user.username, status: 'open' })
		const ticketsCompleted = await Ticket.find({ assigned_to: user.username, status: 'closed' })
		if (!isMatch) {
			return res.render('user-panel', {
				user,
				ticketsInProgress,
				ticketsCompleted,
				error: 'Bieżące hasło jest nieprawidłowe',
			})
		}

		if (newPassword !== confirmPassword) {
			return res.render('user-panel', { user, ticketsInProgress, ticketsCompleted, error: 'Nowe hasła nie są zgodne' })
		}

		user.password = await bcrypt.hash(newPassword, 10)
		await user.save()
		res.redirect('/user-panel')
	} catch (err) {
		next(err)
	}
})

app.post('/user-panel/upload-avatar', upload.single('avatar'), checkAuth, async (req, res, next) => {
	try {
		const user = await User.findById(req.session.user._id)
		if (!user) {
			return res.redirect('/login')
		}

		user.avatar = req.file.filename
		await user.save()
		res.redirect('/user-panel')
	} catch (err) {
		next(err)
	}
})

// Middleware to check if user is logged in
function checkAuth(req, res, next) {
	if (!req.session.user) {
		return res.redirect('/login-required')
	}
	next()
}

// Middleware to handle errors
app.use((err, req, res, next) => {
	console.error(err.stack)
	res.status(500).send('Coś poszło nie tak!')
})
// Route to render user panel
app.get('/user/panel', async (req, res) => {
	const user = await User.findOne({ username: req.session.user.username })
	const ticketsInProgress = await Ticket.find({ assigned_to: user.username, status: 'in-progress' })
	const ticketsCompleted = await Ticket.find({ assigned_to: user.username, status: 'completed' })
	const sections = await Category.distinct('section')
	res.render('user-panel', { user, ticketsInProgress, ticketsCompleted, sections })
})

// Route to update user profile
app.post('/user/update-profile', async (req, res) => {
	const { firstName, lastName, username, email, phone, password } = req.body
	const hashedPassword = password ? await bcrypt.hash(password, 10) : undefined
	const updateData = { firstName, lastName, username, email, phone }
	if (hashedPassword) {
		updateData.password = hashedPassword
	}
	await User.findOneAndUpdate({ username: req.session.user.username }, updateData)
	req.session.user.username = username
	res.redirect('/user/panel')
})

// Route to change user password
app.post('/user/change-password', async (req, res) => {
	const { currentPassword, newPassword } = req.body
	const user = await User.findOne({ username: req.session.user.username })
	const isMatch = await bcrypt.compare(currentPassword, user.password)
	if (isMatch) {
		const hashedPassword = await bcrypt.hash(newPassword, 10)
		await User.findOneAndUpdate({ username: req.session.user.username }, { password: hashedPassword })
		res.redirect('/user/panel')
	} else {
		res.status(400).send('Obecne hasło jest nieprawidłowe')
	}
}) // Route to render user panel
app.get('/user/panel', async (req, res) => {
	const user = await User.findOne({ username: req.session.user.username })
	const ticketsInProgress = await Ticket.find({ assigned_to: user.username, status: 'in-progress' })
	const ticketsCompleted = await Ticket.find({ assigned_to: user.username, status: 'completed' })
	const sections = await Category.distinct('section')
	res.render('user-panel', { user, ticketsInProgress, ticketsCompleted, sections })
})

// Route to update user profile
app.post('/user/update-profile', async (req, res) => {
	const { firstName, lastName, username, email, phone, password } = req.body
	const hashedPassword = password ? await bcrypt.hash(password, 10) : undefined
	const updateData = { firstName, lastName, username, email, phone }
	if (hashedPassword) {
		updateData.password = hashedPassword
	}
	await User.findOneAndUpdate({ username: req.session.user.username }, updateData)
	req.session.user.username = username
	res.redirect('/user/panel')
})

// Route to change user password
app.post('/user/change-password', async (req, res) => {
	const { currentPassword, newPassword } = req.body
	const user = await User.findOne({ username: req.session.user.username })
	const isMatch = await bcrypt.compare(currentPassword, user.password)
	if (isMatch) {
		const hashedPassword = await bcrypt.hash(newPassword, 10)
		await User.findOneAndUpdate({ username: req.session.user.username }, { password: hashedPassword })
		res.redirect('/user/panel')
	} else {
		res.status(400).send('Obecne hasło jest nieprawidłowe')
	}
})
// Route to handle logout
app.get('/logout', (req, res) => {
	req.session.destroy(err => {
		if (err) {
			return res.status(500).send('Błąd podczas wylogowywania')
		}
		res.redirect('/')
	})
})
// Start server
app.listen(port, () => {
	console.log(`Server running at http://localhost:${port}/`)
})
