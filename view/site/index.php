<?php
add_css("
#app {
    margin: 0;
    padding: 0;
    min-height: 100vh;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
}
.install-wrapper {
    background: white;
    border-radius: 12px;
    box-shadow: 0 20px 40px rgba(0,0,0,0.1);
    overflow: hidden;
    width: 900px;
    min-height: 600px;
    display: flex;
}
.sidebar {
    width: 280px;
    background: #f8f9fa;
    padding: 30px 20px;
    border-right: 1px solid #e9ecef;
}
.sidebar h3 {
    color: #495057;
    font-size: 1.2rem;
    margin-bottom: 25px;
    text-align: center;
}
.sidebar ul {
    list-style: none;
    padding: 0;
    margin: 0;
}
.sidebar li {
    padding: 15px 20px;
    margin-bottom: 8px;
    color: #6c757d;
    font-weight: 500;
    cursor: pointer;
    border-radius: 8px;
    transition: all 0.3s ease;
    position: relative;
}
.sidebar li:before {
    content: '';
    position: absolute;
    left: 0;
    top: 50%;
    transform: translateY(-50%);
    width: 4px;
    height: 0;
    background: #007bff;
    transition: height 0.3s ease;
}
.sidebar li.active {
    background: #e3f2fd;
    color: #007bff;
    font-weight: 600;
}
.sidebar li.active:before {
    height: 100%;
}
.sidebar li.completed {
    color: #28a745;
}
.sidebar li.completed:before {
    background: #28a745;
    height: 100%;
}
.install-container {
    flex: 1;
    padding: 40px;
    position: relative;
}
.install-header {
    text-align: center;
    margin-bottom: 40px;
}
.install-header h2 {
    color: #343a40;
    font-size: 2rem;
    margin-bottom: 10px;
}
.install-header p {
    color: #6c757d;
    font-size: 1rem;
}
.step-content {
    display: none;
    animation: fadeIn 0.3s ease;
}
.step-content.active {
    display: block;
}
@keyframes fadeIn {
    from { opacity: 0; transform: translateY(20px); }
    to { opacity: 1; transform: translateY(0); }
}
.form-group {
    margin-bottom: 20px;
}
.form-label {
    display: block;
    margin-bottom: 8px;
    color: #495057;
    font-weight: 500;
}
.form-control {
    width: 100%;
    padding: 12px 16px;
    border: 2px solid #e9ecef;
    border-radius: 8px;
    font-size: 14px;
    transition: border-color 0.3s ease;
}
.form-control:focus {
    outline: none;
    border-color: #007bff;
    box-shadow: 0 0 0 3px rgba(0,123,255,0.1);
}
.btn {
    padding: 12px 24px;
    border: none;
    border-radius: 8px;
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.3s ease;
    text-decoration: none;
    display: inline-block;
    text-align: center;
}
.btn-primary {
    background: #007bff;
    color: white;
}
.btn-primary:hover {
    background: #0056b3;
    transform: translateY(-2px);
}
.btn-secondary {
    background: #6c757d;
    color: white;
}
.btn-secondary:hover {
    background: #545b62;
}
.btn-success {
    background: #28a745;
    color: white;
}
.btn-success:hover {
    background: #1e7e34;
}
.btn-group {
    display: flex;
    justify-content: space-between;
    margin-top: 30px;
}
.alert {
    padding: 12px 16px;
    border-radius: 8px;
    margin-bottom: 20px;
}
.alert-success {
    background: #d4edda;
    color: #155724;
    border: 1px solid #c3e6cb;
}
.alert-danger {
    background: #f8d7da;
    color: #721c24;
    border: 1px solid #f5c6cb;
}
.alert-info {
    background: #d1ecf1;
    color: #0c5460;
    border: 1px solid #bee5eb;
}
.form-check {
    display: flex;
    align-items: center;
    margin-top: 15px;
}
.form-check-input {
    margin-right: 10px;
}
.progress {
    height: 6px;
    background: #e9ecef;
    border-radius: 3px;
    overflow: hidden;
    margin-bottom: 30px;
}
.progress-bar {
    height: 100%;
    background: linear-gradient(90deg, #007bff, #0056b3);
    transition: width 0.3s ease;
}
.loading {
    display: none;
    text-align: center;
    padding: 20px;
}
.spinner {
    border: 3px solid #f3f3f3;
    border-top: 3px solid #007bff;
    border-radius: 50%;
    width: 30px;
    height: 30px;
    animation: spin 1s linear infinite;
    margin: 0 auto 15px;
}
@keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}
");
view_header(lang("系统安装"));
?>

<div >
    <div class="install-wrapper">
        <div class="sidebar">
            <h3><?php echo lang("安装步骤"); ?></h3>
            <ul>
                <li class="active" data-step="1">
                    <i class="bi bi-file-text"></i>
                    <?php echo lang("1. 许可协议"); ?>
                </li>
                <li data-step="2">
                    <i class="bi bi-hdd"></i>
                    <?php echo lang("2. 环境检测"); ?>
                </li>
                <li data-step="3">
                    <i class="bi bi-database"></i>
                    <?php echo lang("3. 数据库配置"); ?>
                </li>
                <li data-step="4">
                    <i class="bi bi-server"></i>
                    <?php echo lang("4. Redis配置"); ?>
                </li>
                <li data-step="5">
                    <i class="bi bi-person-gear"></i>
                    <?php echo lang("5. 管理员账户"); ?>
                </li>
                <li data-step="6">
                    <i class="bi bi-check-circle"></i>
                    <?php echo lang("6. 完成安装"); ?>
                </li>
            </ul>
        </div>
        
        <div class="install-container">
            <div class="install-header">
                <h2><?php echo lang("NexoPHP 安装向导"); ?></h2>
                <p><?php echo lang("欢迎使用 NexoPHP 框架，请按照向导完成安装"); ?></p>
                <div class="progress">
                    <div class="progress-bar" style="width: 16.67%"></div>
                </div>
            </div>
            
            <form id="install-form">
                <!-- 步骤1: 许可协议 -->
                <div class="step-content active" data-step="1">
                    <h4><?php echo lang("许可协议"); ?></h4>
                    <div class="alert alert-info">
                        <?php echo lang("请仔细阅读以下许可协议，继续安装表示您同意该协议的所有条款。"); ?>
                    </div>
                    <div style="max-height: 300px; overflow-y: auto; border: 1px solid #dee2e6; padding: 20px; border-radius: 8px; background: #f8f9fa;">
                        <h5>MIT License</h5>
                        <p>Copyright (c) 2025 - present NexoPHP Software</p>
                        <p>Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:</p>
                        <p>The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.</p>
                        <p>THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.</p>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="agree_license" required>
                        <label class="form-check-label" for="agree_license">
                            <?php echo lang("我已阅读并同意上述许可协议"); ?>
                        </label>
                    </div>
                    <div class="btn-group">
                        <div></div>
                        <button type="button" class="btn btn-primary" onclick="nextStep(2)"><?php echo lang("下一步"); ?></button>
                    </div>
                </div>
                
                <!-- 步骤2: 环境检测 -->
                <div class="step-content" data-step="2">
                    <h4><?php echo lang("环境检测"); ?></h4>
                    <div id="env-check-results">
                        <div class="loading">
                            <div class="spinner"></div>
                            <p><?php echo lang("正在检测系统环境..."); ?></p>
                        </div>
                    </div>
                    <div class="btn-group">
                        <button type="button" class="btn btn-secondary" onclick="prevStep(1)"><?php echo lang("上一步"); ?></button>
                        <button type="button" class="btn btn-primary" id="env-next-btn" onclick="nextStep(3)" disabled><?php echo lang("下一步"); ?></button>
                    </div>
                </div>
                
                <!-- 步骤3: 数据库配置 -->
                <div class="step-content" data-step="3">
                    <h4><?php echo lang("数据库配置"); ?></h4>
                    <div class="form-group">
                        <label class="form-label"><?php echo lang("数据库主机"); ?></label>
                        <input type="text" id="db_host" name="db_host" class="form-control" value="127.0.0.1" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label"><?php echo lang("数据库端口"); ?></label>
                        <input type="number" id="db_port" name="db_port" class="form-control" value="3306" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label"><?php echo lang("数据库名称"); ?></label>
                        <input type="text" id="db_name" name="db_name" class="form-control" placeholder="nexo" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label"><?php echo lang("数据库用户名"); ?></label>
                        <input type="text" id="db_user" name="db_user" class="form-control" value="root" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label"><?php echo lang("数据库密码"); ?></label>
                        <input type="password" id="db_pass" name="db_pass" class="form-control">
                    </div>
                    <div id="db-test-result"></div>
                    <div class="btn-group">
                        <button type="button" class="btn btn-secondary" onclick="prevStep(2)"><?php echo lang("上一步"); ?></button>
                        <button type="button" class="btn btn-primary" onclick="testDatabase()"><?php echo lang("测试连接"); ?></button>
                    </div>
                </div>
                
                <!-- 步骤4: Redis配置 -->
                <div class="step-content" data-step="4">
                    <h4><?php echo lang("Redis配置"); ?></h4>
                    <div class="form-group">
                        <label class="form-label"><?php echo lang("Redis主机"); ?></label>
                        <input type="text" id="redis_host" name="redis_host" class="form-control" value="127.0.0.1" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label"><?php echo lang("Redis端口"); ?></label>
                        <input type="number" id="redis_port" name="redis_port" class="form-control" value="6379" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label"><?php echo lang("Redis密码"); ?></label>
                        <input type="password" id="redis_pass" name="redis_pass" class="form-control" placeholder="<?php echo lang('留空表示无密码'); ?>">
                    </div>
                    <div id="redis-test-result"></div>
                    <div class="btn-group">
                        <button type="button" class="btn btn-secondary" onclick="prevStep(3)"><?php echo lang("上一步"); ?></button>
                        <button type="button" class="btn btn-primary" onclick="testRedis()"><?php echo lang("测试连接"); ?></button>
                    </div>
                </div>
                
                <!-- 步骤5: 管理员账户 -->
                <div class="step-content" data-step="5">
                    <h4><?php echo lang("管理员账户"); ?></h4>
                    <div class="form-group">
                        <label class="form-label"><?php echo lang("用户名"); ?></label>
                        <input type="text" id="admin_username" name="admin_username" class="form-control" value="admin" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label"><?php echo lang("手机号"); ?></label>
                        <input type="tel" id="admin_phone" name="admin_phone" class="form-control" placeholder="13800138000" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label"><?php echo lang("密码"); ?></label>
                        <input type="password" id="admin_password" name="admin_password" class="form-control" placeholder="<?php echo lang('至少6位字符'); ?>" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label"><?php echo lang("确认密码"); ?></label>
                        <input type="password" id="admin_password_confirm" name="admin_password_confirm" class="form-control" required>
                    </div>
                    <div class="btn-group">
                        <button type="button" class="btn btn-secondary" onclick="prevStep(4)"><?php echo lang("上一步"); ?></button>
                        <button type="button" class="btn btn-primary" onclick="validateAdmin()"><?php echo lang("下一步"); ?></button>
                    </div>
                </div>
                
                <!-- 步骤6: 完成安装 -->
                <div class="step-content" data-step="6">
                    <h4><?php echo lang("完成安装"); ?></h4>
                    <div class="alert alert-success">
                        <h5><?php echo lang("准备就绪"); ?></h5>
                        <p><?php echo lang("所有配置已完成，点击开始安装按钮完成系统安装。"); ?></p>
                    </div>
                    <div id="install-progress" style="display: none;">
                        <div class="loading">
                            <div class="spinner"></div>
                            <p id="install-status"><?php echo lang("正在安装系统..."); ?></p>
                        </div>
                    </div>
                    <div id="install-success" style="display: none;">
                        <div class="alert alert-success">
                            <h5><?php echo lang("安装成功！"); ?></h5>
                            <p><?php echo lang("系统已成功安装，您现在可以开始使用了。"); ?></p>
                        </div>
                        <div class="text-center">
                            <a href="/admin" class="btn btn-success"><?php echo lang("进入后台管理"); ?></a>
                        </div>
                    </div>
                    <div class="btn-group" id="install-buttons">
                        <button type="button" class="btn btn-secondary" onclick="prevStep(5)"><?php echo lang("上一步"); ?></button>
                        <button type="button" class="btn btn-success" onclick="startInstall()"><?php echo lang("开始安装"); ?></button>
                    </div>
                </div>
            </form>
        </div>
    </div>
</div>

<script>
let currentStep = 1;
let dbConnected = false;
let redisConnected = false;

// 步骤导航
function nextStep(step) {
    if (step === 2 && !document.getElementById('agree_license').checked) {
        alert('<?php echo lang("请先同意许可协议"); ?>');
        return;
    }
    
    // 更新进度条
    const progress = (step / 6) * 100;
    document.querySelector('.progress-bar').style.width = progress + '%';
    
    // 切换步骤
    document.querySelectorAll('.step-content').forEach(el => el.classList.remove('active'));
    document.querySelector(`.step-content[data-step="${step}"]`).classList.add('active');
    
    // 更新侧边栏
    document.querySelectorAll('.sidebar li').forEach(el => {
        el.classList.remove('active');
        if (parseInt(el.dataset.step) < step) {
            el.classList.add('completed');
        }
    });
    document.querySelector(`.sidebar li[data-step="${step}"]`).classList.add('active');
    
    currentStep = step;
    
    // 特殊处理
    if (step === 2) {
        checkEnvironment();
    }
}

function prevStep(step) {
    nextStep(step);
}

// 环境检测
function checkEnvironment() {
    document.querySelector('#env-check-results .loading').style.display = 'block';
    
    fetch('/install/site/check-environment', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'}
    })
    .then(response => response.json())
    .then(data => {
        document.querySelector('#env-check-results .loading').style.display = 'none';
        
        let html = '';
        let allPassed = true;
        
        data.checks.forEach(check => {
            const status = check.passed ? 'success' : 'danger';
            const icon = check.passed ? 'check-circle' : 'x-circle';
            if (!check.passed) allPassed = false;
            
            html += `
                <div class="alert alert-${status}">
                    <i class="bi bi-${icon}"></i>
                    <strong>${check.name}</strong>: ${check.message}
                </div>
            `;
        });
        
        document.getElementById('env-check-results').innerHTML = html;
        document.getElementById('env-next-btn').disabled = !allPassed;
    })
    .catch(error => {
        document.querySelector('#env-check-results .loading').style.display = 'none';
        document.getElementById('env-check-results').innerHTML = `
            <div class="alert alert-danger">
                <i class="bi bi-x-circle"></i>
                <?php echo lang("环境检测失败，请检查网络连接"); ?>
            </div>
        `;
    });
}

// 测试数据库连接
function testDatabase() {
    const data = {
        host: document.getElementById('db_host').value,
        port: document.getElementById('db_port').value,
        name: document.getElementById('db_name').value,
        user: document.getElementById('db_user').value,
        pass: document.getElementById('db_pass').value
    };
    
    document.getElementById('db-test-result').innerHTML = `
        <div class="loading">
            <div class="spinner"></div>
            <p><?php echo lang("正在测试数据库连接..."); ?></p>
        </div>
    `;
    
    fetch('/install/site/test-database', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(result => {
        const status = result.code == 0 ? 'success' : 'danger';
        const icon = result.code == 0 ? 'check-circle' : 'x-circle';
        
        document.getElementById('db-test-result').innerHTML = `
            <div class="alert alert-${status}">
                <i class="bi bi-${icon}"></i>
                ${result.message}
            </div>
        `;
        
        if (result.code == 0) {
            dbConnected = true;
            setTimeout(() => nextStep(4), 1000);
        }
    })
    .catch(error => {
        document.getElementById('db-test-result').innerHTML = `
            <div class="alert alert-danger">
                <i class="bi bi-x-circle"></i>
                <?php echo lang("连接测试失败，请检查配置"); ?>
            </div>
        `;
    });
}

// 测试Redis连接
function testRedis() {
    const data = {
        host: document.getElementById('redis_host').value,
        port: document.getElementById('redis_port').value,
        pass: document.getElementById('redis_pass').value
    };
    
    document.getElementById('redis-test-result').innerHTML = `
        <div class="loading">
            <div class="spinner"></div>
            <p><?php echo lang("正在测试Redis连接..."); ?></p>
        </div>
    `;
    
    fetch('/install/site/test-redis', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(result => {
        const status = result.code == 0 ? 'success' : 'danger';
        const icon = result.code == 0 ? 'check-circle' : 'x-circle';
        
        document.getElementById('redis-test-result').innerHTML = `
            <div class="alert alert-${status}">
                <i class="bi bi-${icon}"></i>
                ${result.message}
            </div>
        `;
        
        if (result.code == 0) {
            redisConnected = true;
            setTimeout(() => nextStep(5), 1000);
        }
    })
    .catch(error => {
        document.getElementById('redis-test-result').innerHTML = `
            <div class="alert alert-danger">
                <i class="bi bi-x-circle"></i>
                <?php echo lang("连接测试失败，请检查配置"); ?>
            </div>
        `;
    });
}

// 验证管理员信息
function validateAdmin() {
    const username = document.getElementById('admin_username').value;
    const phone = document.getElementById('admin_phone').value;
    const password = document.getElementById('admin_password').value;
    const confirmPassword = document.getElementById('admin_password_confirm').value;
    
    if (!username || !phone || !password) {
        alert('<?php echo lang("请填写完整的管理员信息"); ?>');
        return;
    }
    
    if (password.length < 6) {
        alert('<?php echo lang("密码至少需要6位字符"); ?>');
        return;
    }
    
    if (password !== confirmPassword) {
        alert('<?php echo lang("两次输入的密码不一致"); ?>');
        return;
    }
    
    if (!/^1[3-9]\d{9}$/.test(phone)) {
        alert('<?php echo lang("请输入正确的手机号码"); ?>');
        return;
    }
    
    nextStep(6);
}

// 开始安装
function startInstall() {
    if (!dbConnected || !redisConnected) {
        alert('<?php echo lang("请先完成数据库和Redis连接测试"); ?>');
        return;
    }
    
    document.getElementById('install-buttons').style.display = 'none';
    document.getElementById('install-progress').style.display = 'block';
    
    const installData = {
        db: {
            host: document.getElementById('db_host').value,
            port: document.getElementById('db_port').value,
            name: document.getElementById('db_name').value,
            user: document.getElementById('db_user').value,
            pass: document.getElementById('db_pass').value
        },
        redis: {
            host: document.getElementById('redis_host').value,
            port: document.getElementById('redis_port').value,
            pass: document.getElementById('redis_pass').value
        },
        admin: {
            username: document.getElementById('admin_username').value,
            phone: document.getElementById('admin_phone').value,
            password: document.getElementById('admin_password').value
        }
    };
    
    fetch('/install/site/install', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(installData)
    })
    .then(response => response.json())
    .then(result => {
        document.getElementById('install-progress').style.display = 'none';
        
        if (result.code == 0) {
            document.getElementById('install-success').style.display = 'block';
        } else {
            document.getElementById('install-buttons').style.display = 'flex';
            alert(result.message || '<?php echo lang("安装失败，请重试"); ?>');
        }
    })
    .catch(error => {
        document.getElementById('install-progress').style.display = 'none';
        document.getElementById('install-buttons').style.display = 'flex';
        alert('<?php echo lang("安装过程中发生错误，请重试"); ?>');
    });
}
</script>

<?php view_footer(); ?>