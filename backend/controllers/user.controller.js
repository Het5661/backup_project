const {User,Course,Assignment,Submission} = require('../models/index.model');
const response = require('../utils/responses.util');
const {userValidation} = require('../validations/index.validation');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sendEmail = require('../utils/sendEmail');
const Token = require('../models/token.model');
const crypto = require('crypto');
const joi = require('joi');

const loginUser = async (req, res) => {
    try {
        // check if user exists
        const user = await User.findOne({email: req.body.email});
        if(!user) return response.badRequestResponse(res, 'Email does not exist');
        
        // check if password is correct
        const validPassword = await bcrypt.compare(req.body.password, user.password);
        if(!validPassword) return response.badRequestResponse(res, 'Invalid password');
        
        // create and assign a token
        const token = jwt.sign({id: user._id, email: user.email}, process.env.SECRET || 'default_secret', {expiresIn: '1h'});

        res.set('authorization', token);
        return response.successResponse(res, { token, user });

    } catch (err) {
        console.error('Error in loginUser:', err.message); // Log the error message
        console.error(err.stack); // Log the error stack trace
        return response.serverErrorResponse(res, err);
    }
}

const getAllUsers = async (req, res) => {
    try {
        if(!['ADMIN'].includes(req.role))
            return response.unauthorizedResponse(res);
        const users = await User.find();
        return response.successResponse(res, users);
    } catch (err) {
        console.error('Error in getAllUsers:', err.message); // Log the error message
        console.error(err.stack); // Log the error stack trace
        return response.serverErrorResponse(res, err);
    }
}

const getUserById = async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        return response.successResponse(res, user);
    } catch (err) {
        console.error('Error in getUserById:', err.message); // Log the error message
        console.error(err.stack); // Log the error stack trace
        return response.serverErrorResponse(res, err);
    }
}

const addUser = async (req, res) => {
    try {
        const {error} = userValidation.validate(req.body);
        if(error) return response.badRequestResponse(res, error.details[0].message);

        const user = await User.findOne({email: req.body.email});
        if(user) return response.badRequestResponse(res, 'Email already exists');

        const username = await User.findOne({username: req.body.username});
        if(username) return response.badRequestResponse(res, 'Username already exists');

        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        req.body.password = hashedPassword;

        const newUser = await User.create(req.body);
        return response.successfullyCreatedResponse(res, newUser);
    } catch (err) {
        console.error('Error in addUser:', err.message); // Log the error message
        console.error(err.stack); // Log the error stack trace
        return response.serverErrorResponse(res, err);
    }
}

const deleteUserById = async (req, res) => {
    try {
        if(!['ADMIN'].includes(req.role))
            return response.unauthorizedResponse(res);
        const deletedUser = await User.findByIdAndDelete(req.params.id);
        return response.successResponse(res, deletedUser);
    } catch (err) {
        console.error('Error in deleteUserById:', err.message); // Log the error message
        console.error(err.stack); // Log the error stack trace
        return response.serverErrorResponse(res, err);
    }
}

const updateUserById = async (req, res) => {
    try {
        const updatedUser = await User.findByIdAndUpdate(req.params.id, {
            username: req.body.username,
            phone: req.body.phone,
            email: req.body.email,
        }, { new: true });
        return response.successResponse(res, updatedUser);
    } catch (err) {
        console.error('Error in updateUserById:', err.message); // Log the error message
        console.error(err.stack); // Log the error stack trace
        return response.serverErrorResponse(res, err);
    }
}

const getAllCoursesOfUser = async (req, res) => {
    try {
        const userDetail = await User.findById(req.params.id).populate('courses');
        if (!userDetail) return response.badRequestResponse(res, 'User not found');
        const courses = userDetail.courses;
        let coursesArray = [];
        for(let i=0; i<courses.length; i++){
            const temp = await Course.findById(courses[i]._id).populate('teacher');
            if(!temp) {
                continue;
            }
            let data = {
                instructor: temp.teacher.username,
                course : temp
            }
            coursesArray.push(data);
        }
        return response.successResponse(res, coursesArray);
    } catch (err) {
        console.error('Error in getAllCoursesOfUser:', err.message); // Log the error message
        console.error(err.stack); // Log the error stack trace
        return response.serverErrorResponse(res, err);
    }
}

const addCourseToUser = async (req, res) => {
    try {
        const userId = req.params.id;
        const courseId = req.params.courseId;
        const course = await Course.findById(courseId);
        if(!course) return response.badRequestResponse(res, 'Course does not exist');
        const user = await User.findById(userId);
        if(!user) return response.badRequestResponse(res, 'User does not exist');
        
        const updatedCourse = await Course.findByIdAndUpdate(courseId, {
            $push: {students: userId}
        }, { new: true });
        
        const updatedUser = await User.findByIdAndUpdate(userId, {
            $push: {courses: courseId}
        }, { new: true });
        
        const allAssignments = await Assignment.find({course: courseId});
        for(let i=0; i<allAssignments.length; i++){
            const assignment = allAssignments[i];
            const submissionToAdd = await Submission.create({
                student: req.params.id,
                assignment: assignment._id,
                files : [],
                grade: 0,
                graded: false,
                comments: [],
                feedback : ""
            });
            await Assignment.findByIdAndUpdate(assignment._id, {
                $push: {submissions: submissionToAdd._id}
            });
        }
        
        return response.successResponse(res, {updatedUser, updatedCourse});
    } catch (err) {
        console.error('Error in addCourseToUser:', err.message); // Log the error message
        console.error(err.stack); // Log the error stack trace
        return response.serverErrorResponse(res, err);
    }
}

const changePassword = async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        const validPassword = await bcrypt.compare(req.body.oldPassword, user.password);
        if(!validPassword) return response.badRequestResponse(res, 'Invalid old password');
        const hashedPassword = await bcrypt.hash(req.body.newPassword, 10);
        user.password = hashedPassword;
        await user.save();
        return response.successResponse(res, user);
    } catch (err) {
        console.error('Error in changePassword:', err.message); // Log the error message
        console.error(err.stack); // Log the error stack trace
        return response.serverErrorResponse(res, err);
    }
}

const generateToken = async (req, res) => {
    try {
        const schema = joi.object({ email: joi.string().email().required() });
        const { error } = schema.validate({email: req.query.email});
        if (error) return response.badRequestResponse(res, error.details[0].message);
        const user = await User.findOne({ email: req.query.email });
        if (!user) return response.badRequestResponse(res, "No user found with this email");
        let token = await Token.create({ email: req.query.email,token: crypto.randomBytes(32).toString("hex") });
        const val = await sendEmail(user.email, "Password reset OTP", token.token);
        if(val) return res.send("password reset OTP sent to your email account");
        return res.send("Unable to send OTP to your email account")
    } catch (err) {
        console.error('Error in generateToken:', err.message); // Log the error message
        console.error(err.stack); // Log the error stack trace
        return response.serverErrorResponse(res, err);
    }
}

const resetPassword = async (req, res) => {
    try {
        const token = req.query.token;
        if (!token) return response.badRequestResponse(res, "Invalid token");
        const email = req.query.email;
        const validToken = await Token.find({ email: email });
        for(let i=0; i<validToken.length; i++){
            if(validToken[i].token == token) {
                const user = await User.findOne({ email: email });
                const hashedPassword = await bcrypt.hash(req.query.password, 10);
                user.password = hashedPassword;
                await user.save();
                return response.successResponse(res, "Successfully changed password");
            }
        }
        return response.badRequestResponse(res, "Invalid token");
    } catch (err) {
        console.error('Error in resetPassword:', err.message); // Log the error message
        console.error(err.stack); // Log the error stack trace
        return response.serverErrorResponse(res, err);
    }
}

module.exports = {
    loginUser,
    getAllUsers,
    getUserById,
    addUser,
    deleteUserById,
    updateUserById,
    getAllCoursesOfUser,
    addCourseToUser,
    changePassword,
    generateToken,
    resetPassword
}
