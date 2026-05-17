<?php
// Prevent direct access and set return type to JSON for the AJAX frontend
header('Content-Type: application/json');

// ==========================================
// CONFIGURATION
// ==========================================
$to_email       = "shamim.ansari@careernet.in"; // Replace with the actual recipient email
$from_email     = "noreply@careernet.ae"; // Ensure this matches your server domain to prevent spam flagging
$upload_dir     = __DIR__ . '/uploads/';  // Ensure this directory exists and has 755/777 permissions
$max_file_size  = 5 * 1024 * 1024;        // 5MB limit
$allowed_types  = [
    'application/pdf' => 'pdf',
    'application/msword' => 'doc',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document' => 'docx'
];

// ==========================================
// HELPER FUNCTIONS
// ==========================================

// Function to sanitize input data to prevent XSS and Injection
function sanitize_input($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    return $data;
}

// Function to send JSON response to frontend
function send_response($success, $message) {
    echo json_encode(['success' => $success, 'message' => $message]);
    exit;
}

// Function to send email with attachments natively in PHP
function send_mail_with_attachments($to, $subject, $message, $from, $attachments = []) {
    $boundary = md5(uniqid(time()));
    
    $headers  = "From: $from\r\n";
    $headers .= "Reply-To: $from\r\n";
    $headers .= "MIME-Version: 1.0\r\n";
    $headers .= "Content-Type: multipart/mixed; boundary=\"$boundary\"\r\n";

    // Email Body
    $body  = "--$boundary\r\n";
    $body .= "Content-Type: text/plain; charset=UTF-8\r\n";
    $body .= "Content-Transfer-Encoding: 7bit\r\n\r\n";
    $body .= $message . "\r\n\r\n";

    // Attachments
    foreach ($attachments as $file_path) {
        if (file_exists($file_path)) {
            $file_size = filesize($file_path);
            $handle = fopen($file_path, "r");
            $content = fread($handle, $file_size);
            fclose($handle);
            
            $content = chunk_split(base64_encode($content));
            $name = basename($file_path);

            $body .= "--$boundary\r\n";
            $body .= "Content-Type: application/octet-stream; name=\"$name\"\r\n";
            $body .= "Content-Transfer-Encoding: base64\r\n";
            $body .= "Content-Disposition: attachment; filename=\"$name\"\r\n\r\n";
            $body .= $content . "\r\n\r\n";
        }
    }
    $body .= "--$boundary--";

    return mail($to, $subject, $body, $headers);
}

// ==========================================
// MAIN PROCESSING LOGIC
// ==========================================

// Ensure it's a POST request
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    send_response(false, "Invalid request method.");
}

// Identify the form type
$form_type = sanitize_input($_POST['form_type'] ?? '');
if (empty($form_type)) {
    send_response(false, "Unknown form submission.");
}

// ------------------------------------------
// 1. Shared Field Validations
// ------------------------------------------
$email = sanitize_input($_POST['Email'] ?? '');
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    send_response(false, "Please provide a valid email address.");
}

$phone = sanitize_input($_POST['Phone'] ?? '');
if (!preg_match('/^[0-9\-\+\s\(\)]+$/', $phone)) {
    send_response(false, "Please provide a valid phone number.");
}

// Dynamic Country Code Logic
$country_code = sanitize_input($_POST['Country_Code'] ?? '');
if ($country_code === 'other') {
    $country_code = sanitize_input($_POST['Custom_Country_Code'] ?? '');
    if (empty($country_code)) {
        send_response(false, "Please enter your custom country code.");
    }
}
$full_phone = $country_code . ' ' . $phone;

// Variables to build email
$subject = "";
$email_message = "";
$attachments = [];

// ------------------------------------------
// 2. Specific Form Validations
// ------------------------------------------

if ($form_type === 'contact_corporate' || $form_type === 'hire') {
    // --- Corporate / Hire Forms ---
    $name = sanitize_input($_POST['Name'] ?? '');
    $company = sanitize_input($_POST['Company_Name'] ?? '');
    $user_message = sanitize_input($_POST['Message'] ?? '');

    if (empty($name) || empty($company)) {
        send_response(false, "Name and Company are required fields.");
    }

    $subject = ($form_type === 'hire') ? "New Hiring Inquiry from $name" : "New Corporate Contact from $name";
    
    $email_message .= "You have received a new Corporate/Hiring inquiry.\n\n";
    $email_message .= "Name: $name\n";
    $email_message .= "Company: $company\n";
    $email_message .= "Email: $email\n";
    $email_message .= "Phone: $full_phone\n\n";
    $email_message .= "Message:\n" . (!empty($user_message) ? $user_message : "No message provided.");

} elseif ($form_type === 'contact_candidate' || $form_type === 'cv') {
    // --- Candidate / CV Forms ---
    $first_name = sanitize_input($_POST['First_Name'] ?? '');
    $last_name = sanitize_input($_POST['Last_Name'] ?? '');
    $linkedin = sanitize_input($_POST['LinkedIn_URL'] ?? '');

    if (empty($first_name) || empty($last_name)) {
        send_response(false, "First Name and Last Name are required.");
    }

    if (!empty($linkedin) && !preg_match('/^https?:\/\/(www\.)?linkedin\.com\/.*$/i', $linkedin)) {
        send_response(false, "Please provide a valid LinkedIn URL.");
    }

    // Handle File Upload Security
    if (!isset($_FILES['Resume']) || $_FILES['Resume']['error'] === UPLOAD_ERR_NO_FILE) {
        send_response(false, "Resume upload is mandatory.");
    }

    if ($_FILES['Resume']['error'] !== UPLOAD_ERR_OK) {
        send_response(false, "Error uploading the file. Please try again.");
    }

    $file_tmp = $_FILES['Resume']['tmp_name'];
    $file_size = $_FILES['Resume']['size'];
    
    // Check file size
    if ($file_size > $max_file_size) {
        send_response(false, "File size exceeds the 5MB limit.");
    }

    // Verify MIME type for security (stops spoofed file extensions)
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime_type = finfo_file($finfo, $file_tmp);
    finfo_close($finfo);

    if (!array_key_exists($mime_type, $allowed_types)) {
        send_response(false, "Invalid file format. Only PDF, DOC, and DOCX are permitted.");
    }

    // Create secure filename and move file
    if (!is_dir($upload_dir)) {
        if (!mkdir($upload_dir, 0755, true)) {
            send_response(false, "Server configuration error: Cannot create upload directory.");
        }
    }

    $extension = $allowed_types[$mime_type];
    $safe_filename = 'resume_' . time() . '_' . bin2hex(random_bytes(5)) . '.' . $extension;
    $dest_path = $upload_dir . $safe_filename;

    if (!move_uploaded_file($file_tmp, $dest_path)) {
        send_response(false, "Failed to save the uploaded file on the server.");
    }
    
    // Add to attachments array
    $attachments[] = $dest_path;

    $subject = ($form_type === 'cv') ? "New CV Submission from $first_name $last_name" : "New Candidate Application from $first_name $last_name";
    
    $email_message .= "You have received a new Candidate application.\n\n";
    $email_message .= "Name: $first_name $last_name\n";
    $email_message .= "Email: $email\n";
    $email_message .= "Phone: $full_phone\n";
    $email_message .= "LinkedIn: " . (!empty($linkedin) ? $linkedin : "Not provided") . "\n\n";
    $email_message .= "Please find the applicant's resume attached.";

} else {
    send_response(false, "Invalid form type detected.");
}

// ------------------------------------------
// 3. Dispatch Email
// ------------------------------------------

$mail_status = send_mail_with_attachments($to_email, $subject, $email_message, $from_email, $attachments);

// Clean up uploaded files after sending the email (Optional: remove this if you want to keep copies on your server)
foreach ($attachments as $file) {
    if (file_exists($file)) {
        unlink($file); 
    }
}

if ($mail_status) {
    send_response(true, "Your request has been successfully submitted. We will contact you soon.");
} else {
    // If mail() fails, it's usually due to server SMTP configurations.
    send_response(false, "Server was unable to dispatch the email. Please try again later or contact us directly.");
}
?>