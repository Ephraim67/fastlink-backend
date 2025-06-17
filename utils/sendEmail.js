const nodemailer = require('nodemailer');

// Create a transporter object using SMTP
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    secure: process.env.SMTP_SECURE === 'true', // true for 465, false for other ports
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    }
});

// Verify the connection
await transporter.verify();
console.log("Server is ready to send emails");

// Function to send an email
await sendVerificationEmail({
    to: email,
    subject: "Verify your Email",
    text: `Click to verify: ${verificationLink}`,
    html: `<a href="${verificationLink}">Verify Email</a>`
})