<?php
include_once "includes/conexionBD.php";
include_once "includes/funciones.php";
iniciar_sesion_segura();
$mensaje = "";
$intentos = 0;
$ip = $_SERVER['REMOTE_ADDR'];
if ($ip === '::1' || $ip === 'localhost') {
    $ip = '127.0.0.1';
}
$sql_initial_check = "SELECT intentos FROM inic_ses WHERE ip = ? LIMIT 1";
$stmt_init = mysqli_prepare($conexion, $sql_initial_check);
if ($stmt_init) {
    mysqli_stmt_bind_param($stmt_init, "s", $ip);
    mysqli_stmt_execute($stmt_init);
    $res_init = mysqli_stmt_get_result($stmt_init);
    if ($reg_init = mysqli_fetch_assoc($res_init)) {
        $intentos = (int)$reg_init['intentos'];
    }
    mysqli_stmt_close($stmt_init);
}
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $usuario = trim($_POST["username"] ?? "");
    $contrasena = $_POST["password"] ?? "";
    $token_csrf = $_POST["csrf_token"] ?? "";
    $captcha_usuario = trim($_POST["captcha_input"] ?? "");
    if (!validar_token_csrf($token_csrf)) {
        $mensaje = "La solicitud no es válida. Intente nuevamente.";
    } elseif ($usuario === "" || $contrasena === "") {
        $mensaje = "Ingrese su usuario y contraseña.";
    } elseif (strlen($usuario) > 50) {
        $mensaje = "El usuario no es válido.";
    } else {
        $sql_check = "SELECT intentos FROM inic_ses WHERE ip = ? OR usuario = ? LIMIT 1";
        $stmt_check = mysqli_prepare($conexion, $sql_check);
        if ($stmt_check) {
            mysqli_stmt_bind_param($stmt_check, "ss", $ip, $usuario);
            mysqli_stmt_execute($stmt_check);
            $res_check = mysqli_stmt_get_result($stmt_check);
            if ($reg_check = mysqli_fetch_assoc($res_check)) {
                $intentos = (int)$reg_check['intentos'];
            }
            mysqli_stmt_close($stmt_check);
        }
        $filtros_pasados = true;
        if ($intentos >= 3) {
            $momento_creacion = $_SESSION['captcha_creado_en'] ?? 0;
            $tiempo_actual = time();
            if (($tiempo_actual - $momento_creacion) < 5) {
                inic_sec($conexion, $ip, $usuario, $intentos);
                $mensaje = "Petición demasiado rápida. Debes esperar al menos 5 segundos.";
                $filtros_pasados = false;
            } elseif ($captcha_usuario === "" || $captcha_usuario !== ($_SESSION['captcha_texto'] ?? '')) {
                inic_sec($conexion, $ip, $usuario, $intentos);
                $mensaje = "El texto de verificación es incorrecto.";
                $filtros_pasados = false;
            }
        }
        if ($filtros_pasados) {
            $sql = "SELECT e.id_empleado, e.nombre, e.apellido, e.usuario, e.contraseña, e.id_rol, r.nombre AS rol FROM Empleado e INNER JOIN Rol r ON r.id_rol = e.id_rol WHERE e.usuario = ? AND e.activo = 1 LIMIT 1";
            $stmt = mysqli_prepare($conexion, $sql);
            if ($stmt) {
                mysqli_stmt_bind_param($stmt, "s", $usuario);
                mysqli_stmt_execute($stmt);
                $resultado = mysqli_stmt_get_result($stmt);
                $empleado = mysqli_fetch_assoc($resultado);
                mysqli_stmt_close($stmt);
                if ($empleado && password_verify($contrasena, $empleado["contraseña"])) {
                    $sql_clear = "DELETE FROM inic_ses WHERE ip = ? OR usuario = ?";
                    $stmt_clear = mysqli_prepare($conexion, $sql_clear);
                    if ($stmt_clear) {
                        mysqli_stmt_bind_param($stmt_clear, "ss", $ip, $usuario);
                        mysqli_stmt_execute($stmt_clear);
                        mysqli_stmt_close($stmt_clear);
                    }
                    unset($_SESSION['captcha_texto']);
                    unset($_SESSION['captcha_creado_en']);
                    session_regenerate_id(true);
                    $_SESSION["usuario_id"] = (int) $empleado["id_empleado"];
                    $_SESSION["usuario"] = $empleado["usuario"];
                    $_SESSION["nombre_usuario"] = $empleado["nombre"] . " " . $empleado["apellido"];
                    $_SESSION["id_rol"] = (int) $empleado["id_rol"];
                    $_SESSION["rol"] = $empleado["rol"];
                    header("Location: index.php");
                    exit();
                }
                inic_sec($conexion, $ip, $usuario, $intentos);
                $mensaje = "Usuario o contraseña incorrectos.";
            } else {
                error_log("Error MySQL al preparar login: " . mysqli_error($conexion));
                inic_sec($conexion, $ip, $usuario, $intentos);
                $mensaje = "No se pudo procesar el inicio de sesión.";
            }
        }
    }
    $sql_recheck = "SELECT intentos FROM inic_ses WHERE ip = ? OR usuario = ? LIMIT 1";
    $stmt_recheck = mysqli_prepare($conexion, $sql_recheck);
    if ($stmt_recheck) {
        mysqli_stmt_bind_param($stmt_recheck, "ss", $ip, $usuario);
        mysqli_stmt_execute($stmt_recheck);
        $res_recheck = mysqli_stmt_get_result($stmt_recheck);
        if ($reg_recheck = mysqli_fetch_assoc($res_recheck)) {
            $intentos = (int)$reg_recheck['intentos'];
        }
        mysqli_stmt_close($stmt_recheck);
    }
}
if ($intentos >= 3 && !isset($_SESSION['captcha_texto'])) {
    $_SESSION['captcha_texto'] = substr(str_shuffle("ABCDEFGHJKLMNPQRSTUVWXYZ23456789"), 0, 6);
    $_SESSION['captcha_creado_en'] = time();
}
$sql_clean = "DELETE FROM inic_ses WHERE ultimo_intento < NOW() - INTERVAL 30 MINUTE";
mysqli_query($conexion, $sql_clean);
?>
<!DOCTYPE html>
<html lang="es">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title></title>
    <link rel="stylesheet" href="assets/css/login.css">
    <script src="assets/js/login.js" defer></script>
</head>

<body>
    <div class="form-container">
        <form action="login.php" method="POST">
            <h2 class="form-title">Iniciar sesión</h2>
            <p class="form-description">Bienvenido, ingresa tus datos para acceder<br>a tu cuenta.</p>
            <?php if ($mensaje !== ""): ?>
            <p class="form-error" role="alert"><?php echo htmlspecialchars($mensaje, ENT_QUOTES, "UTF-8"); ?></p>
            <?php endif; ?>
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars(obtener_token_csrf(), ENT_QUOTES, "UTF-8"); ?>">
            <div class="input-container">
                <input type="text" name="username" placeholder="Usuario" maxlength="50" required value="<?php echo htmlspecialchars($_POST["username"] ?? "", ENT_QUOTES, "UTF-8"); ?>">
                <img src="assets/img/login/light-user.svg" class="icon-user">
            </div>
            <div class="input-container">
                <input type="password" name="password" placeholder="Contraseña" required>
                <img src="assets/img/login/light-lock.svg" class="icon-lock">
                <img src="assets/img/login/light-eye.svg" class="icon-password">
            </div>
            <a href="" class="forgot-password">¿Olvidaste tu contraseña?</a>
            <?php if ($intentos >= 3): ?>
            <div style="margin-bottom:12px; background:#f8d7da; color:#721c24; padding:12px; border-radius:4px; border:1px solid #f5c6cb; box-sizing:border-box; max-width:320px; margin-left:auto; margin-right:auto;">
                <p style="margin:0 0 8px 0; font-size:13px; font-weight:bold; text-align:left;">Escriba el código de seguridad:</p>
                <div style="display:flex; gap:10px; align-items:center;">
                    <div style="font-size:14px; font-weight:bold; background:#ffffff; padding:7px 12px; border-radius:4px; border:1px solid #ccc; user-select:none; min-width:80px; text-align:center;">
                        <?php echo $_SESSION['captcha_texto'] ?? ''; ?>
                    </div>
                    <input type="text" name="captcha_input" placeholder="Código" required autocomplete="off" style="flex:1; padding:7px; font-size:14px; border:1px solid #ccc; border-radius:4px; box-sizing:border-box; text-transform:uppercase;">
                </div>
            </div>
            <?php endif; ?>
            <button type="submit" class="btn-login">Iniciar sesión</button>
        </form>
    </div>
    <footer>
        <div class="footer-left">
            <p>&copy; 2026 JBM. Todos los derechos reservados.</p>
        </div>
        <div class="footer-right">
            <div class="about-us" id="openPopup">Sobre nosotros</div>
            <div class="language">ES</div>
            <img src="assets/img/login/light-sun.svg" class="icon-theme">
        </div>
    </footer>
    <?php include_once "about-us.php"; ?>
</body>

</html>
