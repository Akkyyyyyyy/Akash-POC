import nodemailer from 'nodemailer';
import dotenv from 'dotenv';


dotenv.config();

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER, // Your email address
    pass: process.env.EMAIL_PASS, // Your email password or app password
  },
});

export const sendEmail = async ({ to, subject, message }) => {
  try {
    console.log("subject:", subject);
    const mailOptions = {
      from: process.env.EMAIL_USER, // Your email address
      to: to,
      subject: subject,
      html: message,  // Use html for HTML content or use 'text' for plain text
    };
    console.log(mailOptions);
    await transporter.sendMail(mailOptions);
    console.log('Email sent successfully');
  } catch (error) {
    console.error('Error sending email:', error);
  }
}


export const sendOtpEmail = async (to, otp) => {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to,
    subject: 'Your OTP Code',
    text: `Your OTP code is: ${otp}`,
  };
  await transporter.sendMail(mailOptions);
}; 