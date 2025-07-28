<?php 
namespace modules\install\controller;

class SiteController extends \core\AppController
{
    protected $lock_file = '/runtime/install.lock';
    
    protected function init(){
        parent::init();
        $this->lock_file = PATH . $this->lock_file;
        
        // 检查是否已安装
        if (file_exists($this->lock_file) && !in_array($this->action, ['index'])) {
            $msg = lang('系统已安装，如需重新安装请删除install.lock文件');
            echo $msg;

            exit;
        }
    }
    
    public function actionIndex()
    {
        // 如果已安装，跳转到后台
        if (file_exists($this->lock_file)) {
            header('Location: /');
            exit;
        }
    }
    
    /**
     * 环境检测
     */
    public function actionCheckEnvironment()
    {
        $checks = [];
        
        // PHP版本检测
        $phpVersion = PHP_VERSION;
        $checks[] = [
            'name' => 'PHP版本',
            'passed' => version_compare($phpVersion, '7.4.0', '>='),
            'message' => "当前版本: {$phpVersion} (要求: >= 7.4.0)"
        ];
        
        // 必需扩展检测
        $requiredExtensions = ['pdo', 'pdo_mysql', 'json', 'mbstring', 'openssl'];
        foreach ($requiredExtensions as $ext) {
            $checks[] = [
                'name' => "PHP扩展: {$ext}",
                'passed' => extension_loaded($ext),
                'message' => extension_loaded($ext) ? '已安装' : '未安装'
            ];
        }
        
        // Predis检测（检查是否通过Composer安装）
        $predisExists = class_exists('Predis\\Client');
        $checks[] = [
            'name' => 'Predis库',
            'passed' => $predisExists,
            'message' => $predisExists ? '已安装' : '未安装 (请通过Composer安装: composer require predis/predis)'
        ];
        
        // 可选扩展检测
        $optionalExtensions = ['gd',];
        foreach ($optionalExtensions as $ext) {
            $checks[] = [
                'name' => "PHP扩展: {$ext} (可选)",
                'passed' => extension_loaded($ext),
                'message' => extension_loaded($ext) ? '已安装' : '未安装 (建议安装)'
            ];
        }
        
        // 目录权限检测
        $writableDirs = ['/runtime', '/public/uploads', '/config.ini.php'];
        foreach ($writableDirs as $dir) {
            $fullPath = PATH . $dir;
            $dirPath = dirname($fullPath);
            
            if (!is_dir($dirPath)) {
                @mkdir($dirPath, 0755, true);
            }
            
            $writable = is_writable($dirPath);
            $checks[] = [
                'name' => "目录权限: {$dir}",
                'passed' => $writable,
                'message' => $writable ? '可写' : '不可写'
            ];
        }
        
        json_success(['checks' => $checks]);
    }
    
    /**
     * 测试数据库连接
     */
    public function actionTestDatabase()
    {
        $input = json_decode(file_get_contents('php://input'), true);
        
        $host = $input['host'] ?? '';
        $port = $input['port'] ?? 3306;
        $name = $input['name'] ?? '';
        $user = $input['user'] ?? '';
        $pass = $input['pass'] ?? '';
        
        if (empty($host) || empty($name) || empty($user)) {
            json_error(['message' => lang('请填写完整的数据库信息')]);
        }
        
        try {
            $dsn = "mysql:host={$host};port={$port};charset=utf8mb4";
            $pdo = new \PDO($dsn, $user, $pass, [
                \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
                \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC
            ]);
            
            // 检查数据库是否存在，不存在则创建
            $stmt = $pdo->prepare("SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = ?");
            $stmt->execute([$name]);
            
            if (!$stmt->fetch()) {
                $pdo->exec("CREATE DATABASE `{$name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
            }
            
            // 测试连接到指定数据库
            $dsn = "mysql:host={$host};port={$port};dbname={$name};charset=utf8mb4";
            $testPdo = new \PDO($dsn, $user, $pass);
            
            json_success(['message' => lang('数据库连接成功')]);
            
        } catch (\Exception $e) {
            json_error(['message' => lang('数据库连接失败') . ': ' . $e->getMessage()]);
        }
    }
    
    /**
     * 测试Redis连接
     */
    public function actionTestRedis()
    {
        $input = json_decode(file_get_contents('php://input'), true);
        
        $host = $input['host'] ?? '127.0.0.1';
        $port = $input['port'] ?? 6379;
        $pass = $input['pass'] ?? '';
        
        if (!class_exists('Predis\\Client')) {
            json_error(['message' => lang('Predis库未安装，请先通过Composer安装: composer require predis/predis')]);
        }
        
        try {
            // 配置Predis连接参数
            $parameters = [
                'scheme' => 'tcp',
                'host' => $host,
                'port' => $port,
            ];
            
            $options = [
                'connection_timeout' => 5,
                'read_write_timeout' => 5,
            ];
            
            // 如果有密码，添加到参数中
            if (!empty($pass)) {
                $parameters['password'] = $pass;
            }
            
            // 创建Predis客户端
            $redis = new \Predis\Client($parameters, $options);
            
            // 测试连接
            $redis->ping();
            
            // 测试基本操作
            $redis->set('test_key', 'test_value');
            $value = $redis->get('test_key');
            $redis->del('test_key');
            
            if ($value !== 'test_value') {
                throw new \Exception('Redis读写测试失败');
            }
            
            json_success(['message' => lang('Redis连接成功')]);
            
        } catch (\Exception $e) {
            json_error(['message' => lang('Redis连接失败') . ': ' . $e->getMessage()]);
        }
    }
    
    /**
     * 执行安装
     */
    public function actionInstall()
    {
        $input = json_decode(file_get_contents('php://input'), true);
        
        try {
            // 1. 生成配置文件
            $this->generateConfig($input);
            
            // 2. 初始化数据库（使用install_sql函数）
            $this->initDatabase($input['db']);
            
            // 3. 创建管理员账户
            $this->createAdmin($input['admin']);
            
            // 4. 生成安全密钥
            $this->generateSecurityKeys();
            
            // 5. 创建安装锁定文件
            file_put_contents($this->lock_file, date('Y-m-d H:i:s'));
            
            json_success(['message' => lang('安装成功')]);
            
        } catch (\Exception $e) {
            json_error(['message' => lang('安装失败') . ': ' . $e->getMessage()]);
        }
    }
    
    /**
     * 初始化数据库
     */
    private function initDatabase($dbConfig)
    {
        $dsn = "mysql:host={$dbConfig['host']};port={$dbConfig['port']};dbname={$dbConfig['name']};charset=utf8mb4";
        $pdo = new \PDO($dsn, $dbConfig['user'], $dbConfig['pass'], [
            \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION
        ]);
        
        // 使用 install_sql 函数执行 SQL 文件
        $sqlFile = PATH . '/sql/init.sql';
        if (file_exists($sqlFile)) {
            install_sql($sqlFile, function($sql) use ($pdo) {
                $pdo->query($sql);
            });
        }
    }
    
    /**
     * 创建管理员账户
     */
    private function createAdmin($adminConfig)
    { 
        
        // 检查管理员是否已存在
        $existing = db_get_one('user', 'id', ['username' => $adminConfig['username']]);
        if ($existing) {
            throw new \Exception('管理员账户已存在');
        }
        
        // 创建管理员账户数据
        $data = [
            'username' => $adminConfig['username'],
            'password' => password_hash($adminConfig['password'], PASSWORD_DEFAULT),
            'phone' => $adminConfig['phone'] ?? '',
            'tag' => 'admin',
            'created_at' => time(),
            'updated_at' => time()
        ];
        
        $id = db_insert('user', $data);
        
        if (!$id) {
            throw new \Exception('创建管理员账户失败');
        }
    }
    
    /**
     * 生成配置文件
     */
    private function generateConfig($data)
    {
        $configTemplate = file_get_contents(PATH . '/config.ini.dist.php');
        
        // 替换数据库配置
        $configTemplate = str_replace("'127.0.0.1'", "'{$data['db']['host']}'", $configTemplate);
        $configTemplate = str_replace("'root'", "'{$data['db']['user']}'", $configTemplate);
        $configTemplate = str_replace("'111111'", "'{$data['db']['pass']}'", $configTemplate);
        $configTemplate = str_replace("'nexo'", "'{$data['db']['name']}'", $configTemplate);
        $configTemplate = str_replace("'3306'", "'{$data['db']['port']}'", $configTemplate);
        
        // 替换Redis配置
        $configTemplate = preg_replace(
            "/\['redis'\]\['host'\] = '127\.0\.0\.1'/",
            "['redis']['host'] = '{$data['redis']['host']}'",
            $configTemplate
        );
        $configTemplate = preg_replace(
            "/\['redis'\]\['port'\] = '6379'/",
            "['redis']['port'] = '{$data['redis']['port']}'",
            $configTemplate
        );
        $configTemplate = preg_replace(
            "/\['redis'\]\['auth'\] = ''/",
            "['redis']['auth'] = '{$data['redis']['pass']}'",
            $configTemplate
        );
        
        // 生成新的安全密钥
        $aesKey = bin2hex(random_bytes(32));
        $aesIv = bin2hex(random_bytes(16));
        $jwtKey = bin2hex(random_bytes(32));
        
        $configTemplate = preg_replace(
            "/'key' => '[^']+'/",
            "'key' => '{$aesKey}'",
            $configTemplate
        );
        $configTemplate = preg_replace(
            "/'iv' => '[^']+'/",
            "'iv' => '{$aesIv}'",
            $configTemplate
        );
        $configTemplate = preg_replace(
            "/\['jwt_key'\] = md5\('[^']*'\)/",
            "['jwt_key'] = '{$jwtKey}'",
            $configTemplate
        );
        
        // 设置域名
        $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
        $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
        $configTemplate = preg_replace(
            "/\['host'\] = '[^']+'/",
            "['host'] = '{$protocol}://{$host}'",
            $configTemplate
        );
        
        file_put_contents(PATH . '/config.ini.php', $configTemplate);
    }
    
    /**
     * 生成安全密钥
     */
    private function generateSecurityKeys()
    {
        // 创建runtime目录
        $runtimeDir = PATH . '/runtime';
        if (!is_dir($runtimeDir)) {
            mkdir($runtimeDir, 0755, true);
        }
        
        // 创建uploads目录
        $uploadsDir = PATH . '/public/uploads';
        if (!is_dir($uploadsDir)) {
            mkdir($uploadsDir, 0755, true);
        }
        
        // 创建.htaccess文件保护配置文件
        $htaccess = "<Files \"config.ini.php\">\nOrder allow,deny\nDeny from all\n</Files>";
        file_put_contents(PATH . '/.htaccess', $htaccess);
    }
}
