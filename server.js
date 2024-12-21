import express from 'express';
import mongoose from 'mongoose';
import path, { parse } from 'path';
import { fileURLToPath } from 'url';
import cors from 'cors';
import bcrypt from 'bcryptjs'; // Using 'bcrypt' for hashing
import passport from 'passport';
import bodyParser from 'body-parser';
import session from 'express-session';
import { v4 as uuidv4 } from 'uuid';
import multer from 'multer';
import Razorpay from 'razorpay';
import fs from 'fs';

// const router = express.Router();



// Ensure './auth' exports your Passport strategy setup
import './auth.js';

const PORT = 5503;
const router = express.Router();


const app = express();

// ES module workaround for __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


// Middleware
app.use(cors());
app.use(express.json());
// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
// app.use(express.static(__dirname));
app.use(cors());
app.use(bodyParser.json());




// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));


// Serve static files from the mini/vcard directory  
app.use('/mini/vcard', express.static(path.join(__dirname, 'mini/vcard')));



// Update the static path to include the exact directory where your `index.html` file is located

app.use(express.static(path.join(__dirname, 'mini/vcard')));

// function ensureAuthenticated(req, res, next) {
//     if (req.session && req.session.user) {
//         return next(); // User is authenticated, proceed to the next middleware or route
//     }
//     res.redirect('/login'); // Redirect to the login page if not authenticated
// }
const ensureAuthenticated = (req, res, next) => {
    if (!req.session || !req.session.user) {
        return res.status(401).redirect('/login.html'); // Redirect to login if not authenticated
    }
    next();
};




app.get('/home', (req, res) => {
    // Update this path to reflect the correct location of slots2.html
    res.sendFile(path.join(__dirname, '/home.html'));

});


// Serve the main HTML file
app.get('/mini/vcard/slots2.html', (req, res) => {
    // Update this path to reflect the correct location of slots2.html
    res.sendFile(path.join(__dirname, '/slots2.html'));

});
app.get('/patient', (req, res) => {

    res.sendFile(path.join(__dirname, '/patient.html'));

});


app.get('/verifiedPage', (req, res) => {
    res.sendFile(path.join(__dirname, '/verifiedPage.html'));

});
// mini/vcard/doctorhome.html
app.get('/doctorhome', (req, res) => {

    res.sendFile(path.join(__dirname, '/doctorhome.html'));

});
app.get('/docSchedular', (req, res) => {

    res.sendFile(path.join(__dirname, '/docSchedular.html'));

});
app.get('/404', (req, res) => {

    res.sendFile(path.join(__dirname, '/404.html'));

});

app.get('/index', (req, res) => {
    res.sendFile(path.join(__dirname, '/index.html'));
});

app.get('/Docprofile', (req, res) => {
    res.sendFile(path.join(__dirname, '/profile/Docprofile.html'));
});
app.get('/Patprofile', (req, res) => {
    res.sendFile(path.join(__dirname, '/profile/Patprofile.html'));
});



app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '/PMSreg.html'));
});
app.get('/PMSreg', (req, res) => {
    res.sendFile(path.join(__dirname, '/PMSreg.html'));
});

app.get('/Docregister', (req, res) => {
    res.sendFile(path.join(__dirname, '/Docregister.html'));
});


app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, '/login.html'));

});
app.get('/Myappointment', (req, res) => {
    res.sendFile(path.join(__dirname, '/Myappointment.html'));

});

app.get('/indexpay', (req, res) => {
    res.sendFile(path.join(__dirname, '/indexpay.html'));

});


// Route to serve the success page
//  app.get('/payment-success', (req, res) => {
//     res.sendFile(path.join(__dirname, '/vcard/sucess.html'));
//     });


app.get('/doctor-detail', (req, res) => {
    res.sendFile(path.join(__dirname, '/profile/uploads/doctor-detail.html'));

});
app.post('/logout', (req, res) => {
    if (req.session) {
        req.session.destroy((err) => {
            if (err) {
                return res.status(500).send("Failed to destroy session.");
            }
            res.clearCookie('connect.sid');  // Clear the session cookie
            res.redirect('/login');          // Redirect to login page
        });
    } else {
        res.status(400).send("No session found.");
    }
});




// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/doctorinfo')
    .then(() => console.log("Connected to MongoDB"))
    .catch((error) => console.error("Error connecting to MongoDB:", error));


const patientSchema = new mongoose.Schema({
    patientName: { type: String, required: true },
    age: { type: Number, required: true },
    phone: { type: String, required: true },
    doctor: { type: String, required: true },
});

// const Patient = mongoose.model('Patient', patientSchema);
const bookedslot = mongoose.model('bookedSlot', patientSchema);

// Route to handle form submissions
app.post('/submit', async (req, res) => {
    try {
        // Extract data from the request body
        const { patientName, age, phone, doctor } = req.body;

        console.log("Incoming patient data:", req.body);
        // Check if the doctor field is empty  
        if (!doctor) {
            return res.status(400).json({ message: 'Doctor field is required.' });
        }
        // Create and save a new Patient document
        const newPatient = new bookedslot({
            patientName,
            age,
            phone,
            doctor,
        });
        // Save the new patient
        const savedPatient = await newPatient.save();

        console.log("Saved patient data:", savedPatient);

        res.status(201).send({ message: 'Patient data saved successfully!', patient: savedPatient });
    } catch (error) {
        console.error('Error saving patient data:', error);
        res.status(500).send({ error: 'Failed to save patient data' });
    }
});

app.get('/patient/:name', async (req, res) => {
    const { name } = req.params; // Extract doctor name from route parameters
    try {
        // Find all patients with the specified doctor name
        const patients = await bookedslot.find({ doctor: name });

        if (!patients.length) {
            return res.status(404).json({ message: 'No patients found for this doctor' });
        }

        // Respond with the list of patients
        res.json(patients);
    } catch (error) {
        console.error('Server error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});



// --------------------------------------------------------------

// Define Database Schema and Model for Doctor Profiles

const doctorSchema = new mongoose.Schema({
    doctorId: String,
    name: String,
    profession: String,
    rating: Number,
    reviews: Number,
    imageUrl: String,
    patients: Number,
    experience: Number,
    ratings: Number

});

// Database schema and model for profile of doctor
const Ddata = mongoose.model('ddatas', doctorSchema);

// ------------------------------------------------------------------

app.post('/verify', async (req, res) => {
    try {
        const { phone, doctor } = req.body;

        // Validate input
        if (!phone || !doctor) {
            return res.status(400).send({ error: 'Incomplete data' });
        }

        // Query the database to check if the patient exists
        const patient = await bookedslot.findOne({
            phone: phone.trim(),
            doctor: doctor.trim(),
        });
        console.log("Query executed:", { phone, doctor });
        console.log("Query result:", patient);
        if (patient) {
            res.status(200).send({ verified: true, message: 'Verification successful!' });
        } else {
            res.status(404).send({ verified: false, error: 'Data not found' });
        }
    } catch (error) {
        console.error('Error verifying data:', error);
        res.status(500).send({ verified: false, error: 'Server error' });
    }
});




// --------------------------------------------------------------------



// API endpoint to fetch profile
// API endpoint to fetch a specific doctor's profile by doctorId
app.get('/api/profile/:doctorId', async (req, res) => {
    try {
        const doctorId = req.params.doctorId;
        const profile = await Ddata.findOne({ doctorId: doctorId });

        if (profile) {
            console.log("Fetched profile from MongoDB:", profile);
            res.json(profile);
        } else {
            console.warn(`Profile with doctorId ${doctorId} not found.`);
            res.status(404).json({ message: "Profile not found." });
        }
    } catch (error) {
        console.error('Error fetching profile:', error); // Improved error context
        res.status(500).json({ message: "Error fetching profile." });
    }
});





app.get('/api/doctors', async (req, res) => {
    try {
        const doctors = await Ddata.find(); // Fetch all documents
        // res.render('doctors', { doctors }); 
        res.json(doctors);
    } catch (error) {
        res.status(500).json({ error: "Failed to fetch data from the database" });
    }
});







// LOGIN AND REGISTRATION FOR DOC AND PATIENIT
// Configure session middleware
app.use(session({
    secret: 'my-secret-key', // Replace with a strong secret
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: false // Set to true if using HTTPS
    }
}));

// Initialize Passport and restore authentication state, if any, from the session
app.use(passport.initialize());
app.use(passport.session());

// Middleware to check if user is logged in
function isLoggedIn(req, res, next) {
    req.user ? next() : res.sendStatus(401);
}

// Google OAuth2 routes
app.get('/auth/google',
    passport.authenticate('google', { scope: ['email', 'profile'] })
);



app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/auth/google/failure' }),
    (req, res) => {
        // Successful authentication, redirect to success route
        res.redirect('/auth/google/success');
    }
);

// Success route
app.get('/auth/google/success', (req, res) => {
    if (req.isAuthenticated()) {
        res.send(`Hello ${req.user.displayName}, you have successfully logged in!`);
    } else {
        res.redirect('/auth/google/failure');
    }
});

app.get('/auth/google/failure', (req, res) => {
    res.send("Something went wrong");
});

app.get('/auth/protected', isLoggedIn, (req, res) => {
    let name = req.user.displayName;
    res.send(`Hello ${name}`);
});



// Create a Mongoose schema and model
const userSchema = new mongoose.Schema({
    fullname: String,
    email: { type: String, unique: true }, // Ensure email is unique
    mobileno: String,
    password: String,
    role: { type: String, enum: ['doctor', 'patient'], required: true }
});

const User = mongoose.model('users', userSchema);

// Handle user registration
app.post('/register', async (req, res) => {
    const { fullname, email, mobileno, password, role } = req.body;

    try {
        // Check if a user with the given email already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).send('Error: User already registered with this email.');
        }

        const saltRounds = 10;
        const hash = await bcrypt.hash(password, saltRounds);

        // Create a new user instance
        const newUser = new User({
            fullname,
            email,
            mobileno,
            password: hash,
            role
        });

        // Save the new user
        await newUser.save();
        // res.send('User  registered successfully!');
        // res.redirect('/login.html');
        // setTimeout(function () {
        //     // window.location.href = '/login.html';
        //     res.redirect('/Docprofile');
        // }, 2000); // Redirect after 5 seconds
        if (newUser.role === 'patient') {
            setTimeout(function () {
                // window.location.href = '/login.html';
                res.redirect('/patient');
            }, 2000); // Redirect after 5 seconds
        } else if (newUser.role === 'doctor') {
            setTimeout(function () {

                res.redirect('/Docprofile');
            }, 2000); // Redirect after 5 seconds
        }
    } catch (err) {
        // Handle any other errors
        res.status(500).send('Error: ' + err.message);
    }
});


// Handle user login
// app.post('/login', async (req, res) => {
//     const { mobileno, password } = req.body;

//     try {
//         const user = await User.findOne({ mobileno});
//         if (user && await bcrypt.compare(password, user.password)) {
//             req.login(user, (err) => {
//                 if (err) {
//                     return res.status(500).send('Error: ' + err.message);
//                 }
//                 // res.send("Login Successful");


//                 // Redirect based on the user's role
//                 if (user.role === 'doctor') {
//                     res.redirect('/doctorhome.html');
//                 } else if (user.role === 'patient') {
//                     res.redirect('/home.html');
//                 } else {
//                     res.status(403).send("Unauthorized role");
//                 }

//             });
//         } else {
//             res.status(401).send("Invalid credentials");
//         }
//     } catch (error) {
//         console.error(error);
//         res.status(500).send("Server error");
//     }
// });



// Login route
app.post('/login', async (req, res) => {
    const { mobileno, password } = req.body;

    try {
        const user = await User.findOne({ mobileno });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Successful login, check user role
        let redirectUrl = '';
        if (user.role === 'patient') {
            redirectUrl = '/home';
        } else if (user.role === 'doctor') {
            redirectUrl = '/doctorhome';
        }

        // Include `doctorname` in the response
        res.json({
            message: 'Login successful',
            redirect: redirectUrl,
            doctorname: user.fullname // Replace with `user.doctorname` if available
        });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

//*******************(SanJAY)slots creation from doc view

// Doctor schema
const doctorSchema1 = new mongoose.Schema({
    doctorId: { type: String, unique: true, default: uuidv4 },
    profilePhoto: String,
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    phone: String,
    experience: String,
    ratings: { type: Number, default: 0 },
    patients: { type: Number, default: 0 },
});

const Doctor = mongoose.model('Doctor', doctorSchema1);

// Multer setup for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}${path.extname(file.originalname)}`);
    },
});

const upload = multer({ storage });

app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Create a new doctor profile
app.post('/api/profiles', upload.single('profilePhoto'), async (req, res) => {
    try {
        const { name, email, phone, experience, patients } = req.body;
        const doctorData = {
            doctorId: uuidv4(),
            profilePhoto: req.file ? `/uploads/${req.file.filename}` : null,
            name,
            email,
            phone,
            experience,
            patients: patients ? Number(patients) : 0,
        };
        const newDoctor = await Doctor.create(doctorData);
        res.status(201).json(newDoctor);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Failed to create profile.', error: error.message });
    }
});

// Fetch a doctor's profile by doctorId
app.get('/api/profiles/:doctorId', async (req, res) => {
    try {
        const { doctorId } = req.params;
        console.log(`Received request to fetch doctor profile for doctorId: ${doctorId}`); // Debug log

        // Check if doctorId is provided
        if (!doctorId) {
            console.error('doctorId is missing from the request.');
            return res.status(400).json({ message: 'Doctor ID is required.' });
        }

        // Query the database
        const doctor = await Doctor.findOne({ doctorId });
        if (!doctor) {
            console.warn(`No doctor found with doctorId: ${doctorId}`);
            return res.status(404).json({ message: 'Doctor profile not found.' });
        }

        // Send the doctor profile
        res.status(200).json(doctor);
    } catch (error) {
        console.error('Error fetching doctor profile:', error);
        res.status(500).json({ message: 'Failed to fetch profile.', error: error.message });
    }
});


// Fetch schedule for a doctor
app.get('/api/schedules/:doctorId', async (req, res) => {
    try {
        const { doctorId } = req.params;
        const schedule = await Schedule.find({ doctorId });

        if (!schedule || schedule.length === 0) {
            return res.status(404).json({ message: 'Schedule not found' });
        }

        res.status(200).json(schedule);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Failed to fetch schedule.' });
    }
});

const scheduleSchema = new mongoose.Schema({
    date: {
        type: String,
        required: true,
        unique: true // Ensure unique schedules for each date
    },
    slots: {
        morning: {
            type: [String],
            default: []
        },
        afternoon: {
            type: [String],
            default: []
        },
        evening: {
            type: [String],
            default: []
        }
    }
});

const Schedule = mongoose.model('Schedule', scheduleSchema);
//module.exports = Schedule;

// mongoose.connect('mongodb://localhost:27017/clinicScheduler', {
//     useNewUrlParser: true,
//     useUnifiedTopology: true
// }).then(() => console.log('MongoDB connected')).catch(err => console.error(err));

// POST Method: Save or Update Schedule
app.post('/api/schedule', async (req, res) => {
    const { date, slots } = req.body;

    if (!date || !slots) {
        return res.status(400).json({ error: 'Date and slots are required.' });
    }

    try {
        const schedule = await Schedule.findOneAndUpdate(
            { date },
            { slots },
            { upsert: true, new: true } // Create new if not exists, return updated document
        );
        res.status(200).json({ message: 'Schedule saved successfully.', schedule });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to save schedule.' });
    }
});

// GET Method: Fetch Schedule
app.get('/api/schedule/:date', async (req, res) => {
    const { date } = req.params;

    try {
        const schedule = await Schedule.findOne({ date });
        if (!schedule) {
            return res.status(404).json({ error: 'No schedule found for the selected date.' });
        }
        res.status(200).json(schedule);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to fetch schedule.' });
    }
});

// Frontend Changes to Integrate MongoDB
// // Update `populateSlots` to fetch schedule from the backend
async function populateSlots() {
    const today = new Date();
    selectedDate = today.toISOString().split('T')[0];

    availableSlotsDiv.innerHTML = '';
    scheduledSlotsDiv.innerHTML = '';

    const morningTimes = ['10:00 AM', '10:30 AM', '11:00 AM', '11:30 AM'];
    const afternoonTimes = ['12:00 PM', '12:30 PM', '01:00 PM', '01:30 PM', '02:00 PM', '02:30 PM', '03:00 PM'];
    const eveningTimes = ['04:00 PM', '04:30 PM', '05:00 PM', '05:30 PM', '06:00 PM', '06:30 PM', '07:00 PM', '07:30 PM', '08:00 PM', '08:30 PM', '09:00 PM', '09:30 PM'];

    morningTimes.forEach(time => addSlot(availableSlotsDiv, time, 'morning'));
    afternoonTimes.forEach(time => addSlot(availableSlotsDiv, time, 'afternoon'));
    eveningTimes.forEach(time => addSlot(availableSlotsDiv, time, 'evening'));

    // Fetch schedule from backend
    try {
        const response = await fetch(`http://localhost:3000/api/schedule/${selectedDate}`);
        if (response.ok) {
            const data = await response.json();
            loadScheduledSlotsFromBackend(data.slots);
        }
    } catch (err) {
        console.error('Error fetching schedule:', err);
    }
}

function loadScheduledSlotsFromBackend(slots) {
    if (slots) {
        Object.keys(slots).forEach(period => {
            slots[period].forEach(slot => {
                const scheduledSlot = document.createElement('div');
                scheduledSlot.className = 'slot';
                scheduledSlot.textContent = slot;
                scheduledSlot.dataset.period = period;

                const removeLink = document.createElement('span');
                removeLink.textContent = 'Remove';
                removeLink.className = 'slot-remove';
                removeLink.onclick = (e) => {
                    e.stopPropagation();
                    if (confirm('Are you sure you want to remove this slot?')) {
                        removeScheduledSlot(slot, period, scheduledSlot);
                    }
                };

                scheduledSlot.appendChild(removeLink);
                scheduledSlotsDiv.appendChild(scheduledSlot);
            });
        });
    }
}
//patient schema 

const patientProfileSchema = new mongoose.Schema({
    profilePhoto: {
        type: String, // Store the URL or base64 string of the profile photo
        default: 'default-profile.png'
    },
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },
    phone: {
        type: String,
        required: false
    },
    address: {
        streetAddress: {
            type: String,
            required: true
        },
        city: {
            type: String,
            required: true
        },
        state: {
            type: String,
            required: true
        },
        postalCode: {
            type: String,
            required: true
        },
        country: {
            type: String,
            required: true
        }
    },
    bloodGroup: {
        type: String,
        enum: ['A+', 'A-', 'B+', 'B-', 'O+', 'O-', 'AB+', 'AB-'],
        required: true
    }
}, { timestamps: true });
const PatientProfile = mongoose.models.PatientProfile || mongoose.model('PatientProfile', patientProfileSchema);
//   export default PatientProfile;

// Use multer middleware for handling multipart/form-data
router.post('/api/profiles', upload.none(), async (req, res) => {
    try {
        const newProfile = new PatientProfile({
            profilePhoto: req.body.profilePhoto,
            name: req.body.name,
            email: req.body.email,
            phone: req.body.phone,
            address: {
                streetAddress: req.body.streetAddress,
                city: req.body.city,
                state: req.body.state,
                postalCode: req.body.postalCode,
                country: req.body.country
            },
            bloodGroup: req.body.bloodGroup
        });

        const savedProfile = await newProfile.save();
        res.status(201).json({ patientId: savedProfile._id });
    } catch (error) {
        console.error('Error creating profile:', error);
        res.status(500).json({ message: 'Failed to save profile' });
    }
});


//   export default router;

router.get('/api/profiles/:patientId', async (req, res) => {
    try {
        // Fetch the patient profile by patientId
        const patientProfile = await PatientProfile.findById(req.params.patientId);

        if (!patientProfile) {
            return res.status(404).json({ message: 'Profile not found' });
        }
        // Respond with the patient profile data
        res.status(200).json(patientProfile);
    } catch (error) {
        console.error('Error fetching profile:', error);
        res.status(500).json({ message: 'Error retrieving profile' });
    }
});
export { PatientProfile, Schedule };
export default router;


// ***************     PAYment *******************//


const razorpay = new Razorpay({
    key_id: 'rzp_test_QV6MxeOyGOZvxF',
    key_secret: 'vyGKe4ZB0ZX7DArrIEtN2bb7',
});

// Function to read data from JSON file
const readData = () => {
    if (fs.existsSync('orders.json')) {
        const data = fs.readFileSync('orders.json');
        return JSON.parse(data);
    }
    return [];
};
// Function to write data to JSON file
const writeData = (data) => {
    fs.writeFileSync('orders.json', JSON.stringify(data, null, 2));
};
// Initialize orders.json if it doesn't exist
if (!fs.existsSync('orders.json')) {
    writeData([]);
}
// Route to handle order creation
app.post('/create-order', async (req, res) => {
    try {
        const { amount, currency, receipt, notes } = req.body;
        const options = {
            amount: amount * 100, // Convert amount to paise
            currency,
            receipt,
            notes,
        };
        const order = await razorpay.orders.create(options);
        // Read current orders, add new order, and write back to the file
        const orders = readData();
        orders.push({
            order_id: order.id,
            amount: order.amount,
            currency: order.currency,
            receipt: order.receipt,
            status: 'created',
        });
        writeData(orders);
        res.json(order);
    } // Send order details to frontend, including order ID
    catch (error) {
        console.error(error);
        res.status(500).send('Error creating order');
    }
});




app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

