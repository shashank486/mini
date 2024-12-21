import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import mongoose from 'mongoose';
// const PORT = 5000;


const app = express();

// Convert __dirname to ES module equivalent
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);



// Serve the main HTML file
app.get('/', (req, res) => {
    // Update this path to reflect the correct location of slots2.html
    res.sendFile(path.join(__dirname, 'home.html'));

});


// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/doctorinfo')
    .then(() => console.log("Connected to MongoDB"))
    .catch((error) => console.error("Error connecting to MongoDB:", error));

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
    ratings: Number,
    fees:Number,
    clinic:String,
    location:String
});

// Database schema and model for profile of doctor
const Ddata = mongoose.model('ddatas', doctorSchema);

app.get('/api/doctors', async (req, res) => {
    try {
        const doctors = await Ddata.find(); // Fetch all documents
        res.json(doctors); // Return the data in JSON format
    } catch (error) {
        res.status(500).json({ error: "Failed to fetch data from the database" });
    }
});




// // Route to render the index page
// app.get('/', (req, res) => {
//     res.sendFile(path.join(__dirname, '/home.html'));
// });

// Start the server
const port = 5000;
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
