<?php
require_once($_SERVER['DOCUMENT_ROOT'] . '/.core/user/user_table.php');
require_once($_SERVER['DOCUMENT_ROOT'] . '/.core/user/login_attempts_logic.php');
require_once($_SERVER['DOCUMENT_ROOT'] . '/.core/user/validator.php');
require_once($_SERVER['DOCUMENT_ROOT'] . '/.core/.helpers/safe_string.php');
require_once($_SERVER['DOCUMENT_ROOT'] . '/.core/.helpers/authorization.php');

class UserLogic
{
    public static function signUp(
        ?string $email,
        ?string $full_name,
        ?string $birthday,
        ?string $address,
        ?string $gender,
        ?string $interests,
        ?string $vk,
        ?int $blood_type,
        ?string $factor,
        ?string $password_1,
        ?string $password_2
    ) : ?array
    {
        $errors = [];

        if (Authorization::isAuthorized()) {
            $errors['other'] = 'Вы уже авторизованы (перезагрузите страницу).';
            return $errors;
        }

        $email = Validator::sanitizeEmail($email);

        if ($error = Validator::validateEmail($email)) {
            $errors['email'] = $error;
        }
        else {
            $user = UserTable::getByEmail($email ?? null);

            if ($user) {
                $errors['email'] = 'Пользователь с такой почтой уже существует';
            }
        }

        $fields = [
            'full_name' => 'validateName',
            'birthday' => 'validateBirthday',
            'address' => 'validateAddress',
            'gender' => 'validateGender',
            'interests' => 'validateInterests',
            'vk' => 'validateVk',
            'blood_type' => 'validateBloodType',
            'factor' => 'validateFactor',
            'password_1' => 'validatePassword'
        ];

        foreach ($fields as $field => $validator) {
            if ($error = Validator::$validator($$field)) {
                $errors["$field"] = $error;
            }
        }

        if ($password_error = Validator::validatePasswordMatch($password_1, $password_2)) {
            $errors['password_2'] = $password_error;
        }

        if (count($errors)) {
            return $errors;
        }

        $hashed_password = password_hash($password_1, PASSWORD_BCRYPT);

        $user = UserTable::create(
            $email,
            $full_name,
            $birthday,
            $address,
            $gender,
            $interests,
            $vk,
            $blood_type,
            $factor,
            $hashed_password
        );

        if (!$user) {
            $errors['other'] = 'Ошибка добавления пользователя (обратитесь в поддержку)';
            return $errors;
        }

        return null;
    }

    public static function logIn(string $email, string $password) : ?string
    {
        if (Authorization::isAuthorized()) {
            return 'Вы уже авторизованы';
        }

        $email = Validator::sanitizeEmail($email);

        if ($error = Validator::validateEmail($email)) {
            return $error;
        }

        $user_data = UserTable::getByEmail($email);
        if (null == $user_data) {
            return 'Пользователь с таким email не найден';
        }

        $user_id = $user_data['id'];

        $time_until_attempt = LoginAttemptsLogic::timeUntilAllowedAttempt($user_id);

        if (0 !== $time_until_attempt) {
            return 'Превышено количество попыток входа в течение часа.' . '<br>'
                . 'Попробуйте еще раз через ' . SafeString::secondsToMinutesAndSeconds($time_until_attempt);
        }

        $max_attempts = LoginAttemptsLogic::$MAX_ATTEMPTS;

        if (!password_verify($password, $user_data['password'])) {
            LoginAttemptsLogic::addAttempt($user_id);
            $attempts = LoginAttemptsLogic::countAttempts($user_id);

            return $max_attempts - $attempts > 0
                ? 'Неверно указан пароль. Осталось попыток: ' . ($max_attempts - $attempts) . '.'
                : 'Неверно указан пароль.' . '<br>' . 'Попробуйте еще раз через ' .  SafeString::secondsToMinutesAndSeconds(LoginAttemptsLogic::timeUntilAllowedAttempt($user_id));
        }

        LoginAttemptsLogic::resetAttempts($user_id);
        Authorization::setSessionUserId($user_id);

        return null;
    }

    public static function logOut() : void
    {
        Authorization::unsetSessionUserId();
    }

    public static function currentUser() : ?array
    {
        $user_id = Authorization::getSessionUserId();

        if (null == $user_id) {
            return null;
        }

        return UserTable::getById($user_id);
    }
}