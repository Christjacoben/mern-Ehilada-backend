const express = require("express");
const mongoose = require("mongoose");
const { v4: uuidv4 } = require("uuid");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const expressJwt = require("express-jwt");
const nodemailer = require("nodemailer");
const { body, validationResult } = require("express-validator");
const rateLimit = require("express-rate-limit");
const multer = require("multer");
const path = require("path");
require(`dotenv`).config();
const { Schema } = mongoose;

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
const expressStatic = require("express").static;
app.use(bodyParser.json());
app.use(cors());

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs
  message: "Too many requests from this IP, please try again later.",
});

mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on("error", console.error.bind(console, "MongoDB connection error:"));
db.once("open", () => {
  console.log("Connected to MongoDB database!");
});

// Create a Schema and Model for the user data
const userSchema = new mongoose.Schema({
  userId: {
    type: String,
    default: uuidv4(), // Generate a unique ID for each user
    unique: true,
  },
  username: String,
  email: String,
  password: String,
  isAdmin: Boolean,
  otp: String,
  otpCreatedAt: Date,
  joinedClasses: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Class",
    },
  ],
});

const User = mongoose.model("User", userSchema);
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Define a schema and model for your class data
const classSchema = new mongoose.Schema({
  className: String,
  section: String,
  subject: String,
  room: String,
  code: String,
  creator: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
  },
});
const Class = mongoose.model("Class", classSchema);
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Define a schema and model for announcements
const announcementSchema = new mongoose.Schema({
  classId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Class",
    required: true,
  },
  text: {
    type: String,
    required: true,
  },
  link: String,
  file: String,
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

const Announcement = mongoose.model("Announcement", announcementSchema);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
const questionSchema = new Schema({
  classId: {
    type: Schema.Types.ObjectId,
    ref: "Class",
    required: true,
  },
  quizTitle: String,
  dueDateTime: Date,
  scheduleDateTime: Date,
  timeLimit: Number,
  questions: [
    {
      questionId: {
        type: Schema.Types.ObjectId,
        default: () => new mongoose.Types.ObjectId(), // Generate a new ObjectId for each question
        unique: true, // Ensure each question has a unique identifier
      },
      questionType: String,
      questionText: String,
      essayInstructions: String,
      options: [String],
      correctAnswer: Number,
    },
  ],
  file: {
    filePath: String,
  },
  link: String,
});

const Question = mongoose.model("Question", questionSchema);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
const activitySchema = new mongoose.Schema({
  activityTitle: String,
  instructions: String,
  link: String,
  points: Number,
  dueDate: Date,
  scheduleDateTime: Date,
  classId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Class",
  },
});

const Activity = mongoose.model("Activity", activitySchema);
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

const classJoinSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  classDetails: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Class", // Reference to the Class schema
    required: true,
  },
  joinTimestamp: {
    type: Date,
    default: Date.now,
  },
});

const ClassJoin = mongoose.model("ClassJoin", classJoinSchema);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
const submissionSchema = new mongoose.Schema({
  classId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Class", // Reference to the Class schema or the class to which the activity belongs
  },
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User", // Reference to the User schema or the user who submitted the activity
  },

  userLink: String,
  uploadedFile: String, // You can store the file path or details here
  submissionTime: {
    type: Date,
    default: Date.now,
  },
  points: Number,
  activityTitle: String,
});

const Submission = mongoose.model("Submission", submissionSchema);
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
const attendanceSchema = new mongoose.Schema({
  classId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Class",
    required: true,
  },
  attendanceTitle: String,
  dueDateTime: Date,
});

const Attendance = mongoose.model("Attendance", attendanceSchema);
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
const attendanceSubmissionSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User", // Reference to the User schema or the user who submitted the attendance
    required: true,
  },
  classId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Class", // Reference to the Class schema
    required: true,
  },
  attendanceTitle: {
    type: String,
    required: true,
  },
  students: [
    {
      user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User", // Reference to the User schema or the user associated with the student
        required: true,
      },
      name: String,
      isPresent: Boolean,
    },
  ],
  submittedAt: {
    type: Date,
    default: Date.now,
  },
});

const AttendanceSubmission = mongoose.model(
  "AttendanceSubmission",
  attendanceSubmissionSchema
);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
const userQuizSubmissionSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  classId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Class",
    required: true,
  },
  quizTitle: String,
  submissions: [
    {
      questionUserAnswerPairs: [
        {
          question: String,
          answer: String,
        },
      ],
      userScore: Number,
      submittedAt: {
        type: Date,
        default: Date.now,
      },
    },
  ],
  essayAnswer: String,
  file: {
    filePath: String,
  },
});

const UserQuizSubmission = mongoose.model(
  "UserQuizSubmission",
  userQuizSubmissionSchema
);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Set up multer for file uploads
// Define a storage engine for multer
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    // Define the destination directory for uploaded files
    cb(null, "uploads/"); // You can change the directory as needed
  },
  filename: function (req, file, cb) {
    // Define the filename for the uploaded file
    cb(null, Date.now() + "-" + file.originalname);
  },
});

const upload = multer({ storage: storage });
// Middleware to parse JSON requests
app.use(express.json());
// Serve static files from the "uploads" directory
app.use("/uploads", expressStatic(path.join(__dirname, "uploads")));
app.use("/uploads", express.static("uploads"));

// Secret key for JWT signing (should be kept secret in a real application)
const JWT_SECRET_KEY = "mysecretkey";

// Middleware to authenticate user using JWT
const authenticateJwt = expressJwt({
  secret: JWT_SECRET_KEY,
  algorithms: ["HS256"],
}).unless({
  path: [
    "/api/login",
    "/api/signup",
    "/api/forgotpassword",
    "/api/resetpassword",
  ],
});

const isAdmin = (req, res, next) => {
  // Check if the user is authenticated and is an admin
  if (req.user && req.user.isAdmin) {
    next(); // User is an admin, proceed to the next middleware/route handler
  } else {
    res.status(403).json({ error: "Unauthorized" }); // User is not an admin, deny access
  }
};
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// route for update class info
app.put("/api/classes/:classId", authenticateJwt, async (req, res) => {
  const { classId } = req.params;
  const { className, section, subject, room } = req.body; // Assuming the request body contains the updated data

  try {
    const updatedClass = await Class.findByIdAndUpdate(
      classId,
      { className, section, subject, room },
      { new: true }
    );

    if (!updatedClass) {
      return res.status(404).json({ error: "Class not found" });
    }

    res.status(200).json({ message: "Class updated successfully" });
  } catch (error) {
    console.error("Error updating class:", error);
    res.status(500).json({ error: "Error updating class" });
  }
});
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//route to delete class
app.delete("/api/classes/:classId", authenticateJwt, async (req, res) => {
  const { classId } = req.params;

  try {
    // Find the class by ID and remove it from the database
    const deletedClass = await Class.findByIdAndRemove(classId);

    if (!deletedClass) {
      return res.status(404).json({ error: "Class not found" });
    }

    res.status(200).json({ message: "Class deleted successfully" });
  } catch (error) {
    console.error("Error deleting class:", error);
    res.status(500).json({ error: "Error deleting class" });
  }
});
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// route to find all class created
app.get("/api/all-classes", authenticateJwt, async (req, res) => {
  try {
    // Fetch all classes from the database
    const allClasses = await Class.find({});

    res.status(200).json(allClasses);
  } catch (error) {
    console.error("Error fetching classes:", error);
    res.status(500).json({ error: "Error fetching classes" });
  }
});
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//route for update username
app.put("/api/users/:userId/username", authenticateJwt, async (req, res) => {
  const { userId } = req.params;
  const { username } = req.body; // The request body should contain the updated username

  try {
    const updatedUser = await User.findOneAndUpdate(
      { userId: userId },
      { username },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ error: "User not found" });
    }

    res.status(200).json({ message: "Username updated successfully" });
  } catch (error) {
    console.error("Error updating username:", error);
    res.status(500).json({ error: "Error updating username" });
  }
});
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//route for delete user
app.delete("/api/users/:userId", authenticateJwt, async (req, res) => {
  const { userId } = req.params;

  try {
    // Find the user by ID and remove it from the database
    const deletedUser = await User.findOneAndRemove({ userId: userId });

    if (!deletedUser) {
      return res.status(404).json({ error: "User not found" });
    }

    res.status(200).json({ message: "User deleted successfully" });
  } catch (error) {
    console.error("Error deleting user:", error);
    res.status(500).json({ error: "Error deleting user" });
  }
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//route for change password user
app.put(
  "/api/users/:userId/password",
  authenticateJwt,
  isAdmin,
  async (req, res) => {
    const { userId } = req.params;
    const { password } = req.body;

    try {
      // Find the user by the userId field
      const user = await User.findOne({ userId: userId });

      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      // Hash the new password before saving it
      const hashedPassword = await bcrypt.hash(password, 10);
      // Assuming you have a method to update the password securely in your User model
      user.password = hashedPassword;
      await user.save(); // Save the updated password

      res.json({ message: "Password updated successfully" });
    } catch (error) {
      // Log the error to better understand the issue
      console.error("Error updating password:", error);
      res.status(500).json({ error: "Could not update the password" });
    }
  }
);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Define a route to get all user data
app.get("/api/users", authenticateJwt, isAdmin, async (req, res) => {
  try {
    const allUsers = await User.find({}); // Retrieve all user data from the 'User' collection
    res.json(allUsers); // Return the user data as a JSON response
  } catch (error) {
    res.status(500).json({ error: "Could not retrieve user data" });
  }
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

app.post(
  "/api/questions",
  authenticateJwt,
  upload.single("file"),
  async (req, res) => {
    try {
      const {
        classId,
        title,
        dueDateTime,
        scheduleDateTime,
        timeLimit,
        questions,
        link,
      } = req.body;

      if (!classId || !title || !questions) {
        return res.status(400).json({ error: "Invalid request data" });
      }

      // Parse the 'questions' property from a JSON string to an array
      const parsedQuestions = JSON.parse(questions);

      // Check if dueDateTime and scheduleDateTime are provided and convert them to Date objects
      let formattedDueDateTime;
      if (dueDateTime && dueDateTime !== "null") {
        formattedDueDateTime = new Date(dueDateTime);
      } else {
        formattedDueDateTime = null;
      }

      let formattedScheduleDateTime;
      if (scheduleDateTime && scheduleDateTime !== "null") {
        formattedScheduleDateTime = new Date(scheduleDateTime);
      } else {
        formattedScheduleDateTime = null;
      }

      // Get the file path if the file is uploaded
      const filePath = req.file ? req.file.path : null;

      const newQuestion = new Question({
        classId,
        quizTitle: title,
        dueDateTime: formattedDueDateTime,
        scheduleDateTime: formattedScheduleDateTime,
        timeLimit: parseInt(timeLimit, 10) || 0,
        questions: parsedQuestions,
        file: {
          // Store only the file path in the database
          filePath: filePath,
          contentType: req.file ? req.file.mimetype : null,
        },
        link: link || null,
      });

      await newQuestion.save();
      res.status(201).json(newQuestion);
    } catch (error) {
      console.error("Error saving questions:", error);
      res.status(500).json({ error: "Failed to save questions" });
    }
  }
);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

app.post(
  "/api/quiz/submit",
  authenticateJwt,
  upload.single("file"),
  async (req, res) => {
    try {
      const {
        classId,
        user,
        quizTitle,
        questionUserAnswerPairs,
        userScore,
        essayAnswer,
      } = req.body;

      const file = req.file;

      const fileData = {
        filePath: file ? file.path : null,
      };

      const parsedQuestionUserAnswerPairs = JSON.parse(questionUserAnswerPairs);
      // Find the user's existing submissions or create a new submission if none exist
      const existingSubmission = await UserQuizSubmission.findOne({
        user,
        classId,
        quizTitle,
      });

      if (existingSubmission) {
        // Add a new submission to the submissions array
        existingSubmission.submissions.push({
          questionUserAnswerPairs: parsedQuestionUserAnswerPairs,
          userScore,
        });

        // Save the updated submission
        await existingSubmission.save();
      } else {
        // Create a new user quiz submission
        const newSubmission = new UserQuizSubmission({
          user,
          classId,
          quizTitle,
          submissions: [
            {
              questionUserAnswerPairs: parsedQuestionUserAnswerPairs,
              userScore,
            },
          ],
          essayAnswer,
          file: fileData,
        });

        // Save the new submission
        await newSubmission.save();
      }

      res.status(201).json({ message: "Quiz submitted successfully" });
    } catch (error) {
      console.error("Error submitting quiz:", error);
      res.status(500).json({ error: "Failed to submit the quiz" });
    }
  }
);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

app.get("/api/quiz/submissions/:userId", authenticateJwt, async (req, res) => {
  try {
    const userId = req.params.userId;

    // Find all quiz submissions for the specified user
    const userSubmissions = await UserQuizSubmission.find({ user: userId });

    res.status(200).json(userSubmissions);
  } catch (error) {
    console.error("Error fetching quiz submissions:", error);
    res.status(500).json({ error: "Failed to fetch quiz submissions" });
  }
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Add a new route to fetch attendance submissions
app.get("/api/attendance/submissions", authenticateJwt, async (req, res) => {
  try {
    // You can add additional query parameters to filter attendance submissions, if needed
    const attendanceSubmissions = await AttendanceSubmission.find({})
      .populate("user") // Populate the "user" field with user information
      .exec();

    res.status(200).json(attendanceSubmissions);
  } catch (error) {
    console.error("Error fetching attendance submissions:", error);
    res.status(500).json({ error: "Failed to fetch attendance submissions" });
  }
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
app.post("/api/attendance/submit", authenticateJwt, async (req, res) => {
  try {
    const { classId, attendanceTitle, students, user } = req.body;

    // Check if there is an existing attendance record for the given class and title
    let attendanceRecord = await AttendanceSubmission.findOne({
      classId: classId,
      attendanceTitle: attendanceTitle,
    });

    if (!attendanceRecord) {
      // If there is no existing record, create a new one with the first set of students
      attendanceRecord = new AttendanceSubmission({
        classId,
        attendanceTitle,
        students: students.map((student) => ({
          ...student,
          classId: classId,
          user: user, // Add user to each student object
        })),
        user,
      });
    } else {
      // If there is an existing record, update the students list by appending new names
      attendanceRecord.students = [
        ...attendanceRecord.students,
        ...students.map((student) => ({
          ...student,
          classId: classId,
          user: user, // Add user to each student object
        })),
      ];
      attendanceRecord.user = user;
    }

    // Save or update the attendance record in the database
    await attendanceRecord.save();

    res.status(201).json({ message: "Attendance submitted successfully" });
  } catch (error) {
    console.error("Error submitting attendance:", error);
    res.status(500).json({ error: "Failed to submit attendance" });
  }
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

app.get("/api/attendance/:classId", authenticateJwt, async (req, res) => {
  try {
    const classId = req.params.classId;
    // Fetch attendance data for the specified classId
    const attendanceData = await Attendance.find({ classId });

    res.status(200).json(attendanceData);
  } catch (error) {
    console.error("Error fetching attendance data:", error);
    res.status(500).json({ error: "Failed to fetch attendance data" });
  }
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
app.post("/api/attendance", authenticateJwt, async (req, res) => {
  try {
    const { classId, attendanceTitle, dueDateTime } = req.body;

    // Here, you can create a new document in your MongoDB to store the attendance data
    const newAttendance = new Attendance({
      classId,
      attendanceTitle,
      dueDateTime,
    });

    // Save the attendance data to the database
    await newAttendance.save();

    res.status(201).json({ message: "Attendance data saved successfully" });
  } catch (error) {
    console.error("Error saving attendance data:", error);
    res.status(500).json({ error: "Failed to save attendance data" });
  }
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// route for saving answered activity
app.post(
  "/api/submit-activity",
  authenticateJwt,
  upload.single("uploadedFile"),
  async (req, res) => {
    try {
      const { classId, userLink, points, activityTitle } = req.body;
      const user = req.user.userId;

      // Find an existing submission with the same activityTitle
      const existingSubmission = await Submission.findOne({
        activityTitle,
      }).populate("user");

      if (existingSubmission) {
        // An existing submission with the same activityTitle is found, so update it

        if (userLink) {
          existingSubmission.userLink = userLink;
        }

        if (req.file) {
          existingSubmission.uploadedFile = req.file.path;
        }

        if (points) {
          existingSubmission.points = points;
        }

        // Save the updated submission
        await existingSubmission.save();

        return res
          .status(200)
          .json({ message: "Activity updated successfully" });
      } else {
        // Create a new submission record
        const submission = new Submission({
          classId,
          user,
          userLink,
          uploadedFile: req.file ? req.file.path : null,
          points,
          activityTitle,
        });

        await submission.save();
        res.status(201).json({ message: "Activity submitted successfully" });
      }
    } catch (error) {
      console.error("Error submitting/updating activity:", error);
      res.status(500).json({ error: "Failed to submit/update activity" });
    }
  }
);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Define a route to fetch submitted activities
app.get(
  "/api/fetch-submitted-activities/:userId",
  authenticateJwt,
  async (req, res) => {
    try {
      const userId = req.params.userId;

      // Query the database to find all submissions for a specific user (assuming a one-to-many relationship between users and submissions)
      const submittedActivities = await Submission.find({ user: userId });

      res.status(200).json(submittedActivities);
    } catch (error) {
      console.error("Error fetching submitted activities:", error);
      res.status(500).json({ error: "Failed to fetch submitted activities" });
    }
  }
);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Add this route save created activity
app.post("/api/activities", authenticateJwt, async (req, res) => {
  try {
    const {
      activityTitle,
      instructions,
      link,
      points,
      dueDate,
      scheduleDateTime,
      classId, // You can pass the classId from the frontend to associate activities with a class.
    } = req.body;

    const newActivity = new Activity({
      activityTitle,
      instructions,
      link,
      points,
      dueDate: new Date(dueDate), // Parse dueDate as a Date
      scheduleDateTime: scheduleDateTime ? new Date(scheduleDateTime) : null,
      classId, // Use the 'class' field to associate the activity with the class
    });

    await newActivity.save();
    res.status(201).json(newActivity);
  } catch (error) {
    console.error("Error saving activity:", error);
    res.status(500).json({ error: "Failed to save activity" });
  }
});
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Add this route for fetching all activity
app.get("/api/activities", authenticateJwt, async (req, res) => {
  try {
    const { classId, activityTitle } = req.query;

    // Fetch activities based on the provided classId
    const activities = await Activity.find({ classId, activityTitle });

    res.status(200).json(activities);
  } catch (error) {
    console.error("Error fetching activities:", error);
    res.status(500).json({ error: "Failed to fetch activities" });
  }
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Add this route for fetching title
app.get("/api/activities/:classId", authenticateJwt, async (req, res) => {
  try {
    const classId = req.params.classId;
    const activities = await Activity.find({ classId }).exec();
    res.status(200).json(activities);
  } catch (error) {
    console.error("Error fetching activities:", error);
    res.status(500).json({ error: "Failed to fetch activities" });
  }
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Add a new route for quiz submissions

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Create an API endpoint to fetch submitted quizzes
// Import necessary modules and models

// Define a new route for retrieving submitted quizzes
app.get("/api/quiz/submissions", authenticateJwt, async (req, res) => {
  try {
    const { user, classId, quizTitle } = req.query;

    // Find the user's submitted quiz based on user, classId, and quizTitle
    const existingSubmission = await UserQuizSubmission.findOne({
      user,
      classId,
      quizTitle,
    });

    if (existingSubmission) {
      res.status(200).json(existingSubmission);
    } else {
      res
        .status(404)
        .json({ message: "No submission found for the specified criteria" });
    }
  } catch (error) {
    console.error("Error retrieving submitted quiz:", error);
    res.status(500).json({ error: "Failed to retrieve the submitted quiz" });
  }
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Add this route for quiz code

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Add this route to your backend cod
app.get("/api/quizzes/:classId", authenticateJwt, async (req, res) => {
  try {
    const { classId } = req.params;

    // Query the database to find quizzes based on classId
    const quizzes = await Question.find({ classId }).exec();

    res.status(200).json(quizzes);
  } catch (error) {
    console.error("Error fetching quizzes:", error);
    res.status(500).json({ error: "Failed to fetch quizzes" });
  }
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Route for fetching quiz titles
app.get("/api/quiz-titles", authenticateJwt, async (req, res) => {
  try {
    const classId = req.query.classId;

    // Fetch quiz titles and due date from the database
    const quizzes = await Question.find(
      { classId },
      { quizTitle: 1, dueDateTime: 1, timeLimit: 1, scheduleDateTime: 1 }
    );

    res.status(200).json(quizzes);
  } catch (error) {
    console.error("Error fetching quiz titles:", error);
    res.status(500).json({ error: "Failed to fetch quiz titles" });
  }
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Route for posting announcements
app.post(
  "/api/announcements",
  authenticateJwt,
  upload.single("file"),
  async (req, res) => {
    try {
      const { classId, text, link } = req.body;
      const fileUrl = req.file ? req.file.path : null; // Get the uploaded file path

      // Create a new announcement object with classId, text, and fileUrl
      const newAnnouncement = new Announcement({
        classId,
        text,
        link,
        file: fileUrl,
      });

      // Save the announcement to MongoDB
      await newAnnouncement.save();

      res.status(201).json(newAnnouncement);
    } catch (error) {
      console.error("Error posting announcement:", error);
      res.status(500).json({ error: "Failed to post announcement" });
    }
  }
); ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Route for fetching announcements by classId
app.get("/api/announcements/:classId", async (req, res) => {
  try {
    const { classId } = req.params;

    const announcements = await Announcement.find({ classId })
      .populate("classId")
      .select("-__v")
      .sort({ createdAt: -1 });

    res.status(200).json(announcements);
  } catch (error) {
    console.error("Error fetching announcements:", error);
    res.status(500).json({ error: "Failed to fetch announcements" });
  }
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Add a route for handling file uploads
app.post("/api/upload", authenticateJwt, upload.single("file"), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded." });
    }
    // You can save the file details to the database or process the file as needed
    const fileDetails = {
      originalName: req.file.originalname,
      fileName: req.file.filename,
      mimeType: req.file.mimetype,
      size: req.file.size,
    };

    // Return the uploaded file details
    res.status(200).json(fileDetails);
  } catch (error) {
    console.error("Error uploading file:", error);
    res.status(500).json({ error: "Error uploading file." });
  }
});
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Define a route for creating a new class
app.post("/api/classes", authenticateJwt, async (req, res) => {
  try {
    const { className, section, subject, room, code } = req.body;

    // Check if any required fields are missing
    if (!className || !section || !subject || !room) {
      return res.status(400).json({ error: "Missing required fields." });
    }

    // Check if the class with the same details already exists
    const existingClass = await Class.findOne({
      className,
      section,
      subject,
      room,
    });
    if (existingClass) {
      return res.status(409).json({ error: "Class already exists." });
    }

    // Create a new class instance using the Class model
    const newClass = new Class({
      className,
      section,
      subject,
      room,
      code,
      creator: req.user.userId,
    });

    // Save the class data to the database
    const savedClass = await newClass.save();

    res.status(201).json(savedClass);
  } catch (error) {
    console.error("Error creating class:", error);
    res.status(500).json({ error: "Error creating class" });
  }
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//fetching classes data
app.get("/api/classes", authenticateJwt, async (req, res) => {
  try {
    // Fetch classes associated with the logged-in user
    const classes = await Class.find({ creator: req.user.userId });

    // Return classes with creator details
    const classesWithCreators = await Promise.all(
      classes.map(async (classInfo) => {
        const creator = await User.findById(classInfo.creator);

        return {
          ...classInfo.toObject(),
          creator: {
            _id: creator._id,
            username: creator.username,
            email: creator.email, // Include creator's email
            // Add more creator details as needed
          },
        };
      })
    );

    res.status(200).json(classesWithCreators);
  } catch (error) {
    console.error("Error fetching classes:", error);
    res.status(500).json({ error: "Error fetching classes" });
  }
});

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// route to save classjoin
app.post("/api/classes/join", authenticateJwt, async (req, res) => {
  try {
    const { classCode, username, email } = req.body;
    const userId = req.user.userId;

    // Find the class based on the class code
    const classInfo = await Class.findOne({ code: classCode });

    if (!classInfo) {
      return res.status(404).json({ error: "Class not found!" });
    }

    // Save the class join information for the user
    const classJoinData = new ClassJoin({
      userId,
      classDetails: classInfo._id,
      joinTimestamp: new Date(),
      username,
    });
    await classJoinData.save();

    console.log(
      `User with ID ${userId} (${username}, ${email}) successfully joined class ${classInfo.className}.`
    );

    res.status(200).json({ message: "Class joined successfully." });
  } catch (error) {
    console.error("Error joining class:", error);
    res.status(500).json({ error: "Error joining class" });
  }
});

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//list join class user
app.get("/api/classes/users/:classId", authenticateJwt, async (req, res) => {
  try {
    const classId = req.params.classId;

    // Find all users who joined the specified class
    const usersInClass = await ClassJoin.find({
      classDetails: classId,
    }).populate({
      path: "userId", // Assuming 'userId' is the field referencing the User model
      select: "username email", // Select the fields you want to retrieve
    });

    // Extract user details if needed
    const usersData = usersInClass.map((user) => ({
      userId: user.userId,
      username: user.username,
      email: user.email,
      joinTimestamp: user.joinTimestamp,
      // Add other relevant user details as needed
    }));

    res.status(200).json(usersData);
  } catch (error) {
    console.error("Error fetching users in class:", error);
    res.status(500).json({ error: "Error fetching users in class" });
  }
});

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Add a route for fetching classjoined information by classId
app.get("/api/classes/joinedWithDetails", authenticateJwt, async (req, res) => {
  try {
    const userId = req.user.userId;

    // Fetch joined classes with username and email
    const joinedClasses = await ClassJoin.find({ userId })
      .populate({
        path: "userId",
        select: "username email", // Specify the fields you want to select
      })
      .populate("classDetails");

    res.status(200).json(joinedClasses);
  } catch (error) {
    console.error("Error fetching joined classes with details:", error);
    res
      .status(500)
      .json({ error: "Error fetching joined classes with details" });
  }
});

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Add a route for fetching class information by join code
app.get("/api/classes/join/:joinCode", authenticateJwt, async (req, res) => {
  try {
    const { joinCode } = req.params;

    // Find the class by join code
    const classInfo = await Class.findOne({ code: joinCode });

    if (!classInfo) {
      return res.status(404).json({ error: "Class not found!" });
    }

    res.status(200).json(classInfo);
  } catch (error) {
    console.error("Error fetching class information:", error);
    res.status(500).json({ error: "Error fetching class information." });
  }
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//Handle POST request for sending OTP for Passsword reset
app.post("/api/forgotpassword", async (req, res) => {
  try {
    const { email } = req.body;

    //Find the user based on email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: "User not found!" });
    }

    // Generate a new OTP
    const otp = Math.floor(1000 + Math.random() * 9000).toString();

    // Save the OTP and its creation time to the user's document
    user.otp = otp;
    user.otpCreatedAt = new Date(); // Fix the typo here
    await user.save();

    // Send the OTP to the user's email
    const transporter = nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 587,
      secure: false,
      auth: {
        user: "ehilada873@gmail.com",
        pass: "lpheeihmwoiizeqj",
      },
    });

    // Listen for errors when sending the email
    transporter.sendMail(
      {
        from: "ehilada-learning.com",
        to: user.email,
        subject: "Forgot Password OTP",
        text: `Your OTP is: ${otp}`,
      },
      (error, info) => {
        if (error) {
          console.error("Error sending email:", error);
          res.status(500).json({ error: "Error sending email." });
        } else {
          console.log("Email sent:", info.response);
          res.status(200).json({ message: "OTP sent to your email." });
        }
      }
    );
  } catch (error) {
    console.error("Error sending OTP", error);
    res.status(500).json({ error: "Error sending OTP." });
  }
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//Handle POST request for resetting the password
app.post("/api/resetpassword", async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;

    // Find the user based on email
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ error: "User not found!" });
    }

    // Check if OTP is valid and not expired (e.g., OTP expires after 10 minutes)
    const otpCreatedAt = new Date(user.otpCreatedAt);
    const currentDateTime = new Date();
    const diffInMinutes = (currentDateTime - otpCreatedAt) / (1000 * 60);

    if (otp !== user.otp || diffInMinutes > 10) {
      return res.status(400).json({ error: "Invalid or expired OTP!" });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the user's password in the database
    user.password = hashedPassword;

    // Clear the OTP fields from the user's document
    user.otp = undefined;
    user.otpCreatedAt = undefined;

    await user.save();

    res.status(200).json({ message: "Password reset successful." });
  } catch (error) {
    console.error("Error resetting password:", error);
    res.status(500).json({ error: "Error resetting password." });
  }
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Handle POST request for signup
app.post(
  "/api/signup",
  [
    body("username").notEmpty().withMessage("Username is required."),
    body("email").isEmail().withMessage("Invalid email format."),
    body("password")
      .notEmpty()
      .withMessage("Password is required.")
      .isLength({ min: 6 })
      .withMessage("Password must be at least 6 characters."),
    body("confirmPassword").custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error("Passwords do not match.");
      }
      return true;
    }),
  ],
  apiLimiter, // Apply rate limiting
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { username, email, password, isAdmin } = req.body;

      // Check if user with the same email exists
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(409).json({ error: "Email already registered." });
      }

      // Hash the password before saving it to the database
      const hashedPassword = await bcrypt.hash(password, 10);

      // Create a new user instance using the model
      const userId = uuidv4();
      const newUser = new User({
        userId,
        username,
        email,
        password: hashedPassword,
        isAdmin,
      });

      // Save the user data to the database
      await newUser.save();

      res.status(201).json({ message: "User signed up successfully!" });
    } catch (error) {
      console.error("Error signing up:", error);
      res.status(500).json({ error: "Error signing up" });
    }
  }
);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Handle POST request for login and issue JWT upon successful login
// Apply validation and rate limiting to the login route
app.post(
  "/api/login",
  [
    body("usernameOrEmail")
      .notEmpty()
      .withMessage("Username or email is required."),
    body("password").notEmpty().withMessage("Password is required."),
  ],
  apiLimiter, // Apply rate limiting
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { usernameOrEmail, password } = req.body;

      // Find the user based on username or email
      const user = await User.findOne({
        $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }],
      }).populate("joinedClasses");

      if (!user) {
        return res.status(404).json({ error: "User not found!" });
      }

      // Compare the provided password with the hashed password in the database
      const passwordMatch = await bcrypt.compare(password, user.password);

      if (!passwordMatch) {
        return res.status(401).json({ error: "Invalid password!" });
      }

      // Generate a JWT token for the user (expires in 1 hour)
      const token = jwt.sign(
        { userId: user._id, isAdmin: user.isAdmin },
        JWT_SECRET_KEY,
        {
          expiresIn: "24h",
        }
      );

      // Return the token to the client upon successful login
      res.status(200).json({ token });
    } catch (error) {
      console.error("Error logging in:", error);
      res.status(500).json({ error: "Error logging in" });
    }
  }
);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Handle POST request for display username
app.get("/api/user/:usernameOrEmail", async (req, res) => {
  try {
    const { usernameOrEmail } = req.params;

    // Find the user based on username or email
    const user = await User.findOne({
      $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }],
    });

    if (!user) {
      return res.status(404).json({ error: "User not found!" });
    }

    // Return the user data without the password and other sensitive information
    const userData = {
      userId: user._id,
      username: user.username,
      email: user.email,
      isAdmin: user.isAdmin,
    };

    res.status(200).json(userData);
  } catch (error) {
    console.error("Error fetching user data:", error);
    res.status(500).json({ error: "Error fetching user data" });
  }
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
app.get("/api/checkAdmin", async (req, res) => {
  try {
    // Check if there is any user with isAdmin set to true
    const adminUser = await User.findOne({ isAdmin: true });

    if (adminUser) {
      res.json({ isAdminCreated: true });
    } else {
      res.json({ isAdminCreated: false });
    }
  } catch (error) {
    console.error("Error checking admin user:", error);
    res.status(500).json({ error: "Error checking admin user" });
  }
});
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Handle POST request for logout
app.post("/api/logout", (req, res) => {
  // Implement any necessary logout logic here
  res.status(200).json({ message: "Logged out successfully." });
});
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Example protected route
app.get("/api/protected", authenticateJwt, (req, res) => {
  // If JWT is valid, req.user will contain the decoded payload (in this case, userId)
  res.status(200).json({ message: "Protected route accessed!" });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
