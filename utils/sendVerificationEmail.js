const nodemailer = require('nodemailer');

// Create the transporter once
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT),
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    }
});

// Verify connection
transporter.verify(function (error, success) {
    if (error) {
        console.error("❌ Email server connection failed:", error);
    } else {
        console.log("✅ Email server is ready to send messages");
    }
});

// Exported function to send email
const sendVerificationEmail = async ({ to, subject, text, html }) => {
    const mailOptions = {
        from: `"${process.env.FROM_NAME}" <${process.env.FROM_EMAIL}>`,
        to,
        subject,
        text,
        html
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log(`✅ Verification email sent to ${to}`);
    } catch (error) {
        console.error(`❌ Failed to send email to ${to}:`, error);
        throw error;
    }
};

module.exports = sendVerificationEmail;
