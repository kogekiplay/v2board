<?php

namespace App\Http\Controllers\V1\Client;

use App\Http\Controllers\Controller;
use App\Protocols\General;
use App\Services\ServerService;
use App\Services\UserService;
use App\Utils\Helper;
use Illuminate\Http\Request;

class ClientController extends Controller
{
    public function subscribe(Request $request)
    {
        $flag = $request->input('flag')
            ?? ($_SERVER['HTTP_USER_AGENT'] ?? '');
        $flag = strtolower($flag);
        $user = $request->user;
        $userip = $request->ip();
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "https://api.ip138.com/ip/?ip=$userip&datatype=jsonp&token=af4f160f352e23f02f1d224dce7bb1d8");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_HEADER, 0);
        // 获取返回的json数据
        $output = curl_exec($ch);
        curl_close($ch);
        // 解析json数据为数组
        // 参考文档：[3]
        $data = json_decode($output, true);
        // 提取地区和isp的值
        // 参考文档：[4]
        $region = $data['data'][0] . $data['data'][1] . $data['data'][2]; // 国家+省份+城市
        $isp = $data['data'][4]; // 运营商
        // 合并地区和isp到一个$result
        // 参考文档：[5]
        $result = "$region - $isp";
        // account not expired and is not banned.
        $userService = new UserService();
        if ($userService->isAvailable($user)) {
            $serverService = new ServerService();
            $servers = $serverService->getAvailableServers($user);
            $this->setSubscribeInfoToServers($servers, $user, $result, $userip);
            if ($flag) {
                foreach (array_reverse(glob(app_path('Protocols') . '/*.php')) as $file) {
                    $file = 'App\\Protocols\\' . basename($file, '.php');
                    $class = new $file($user, $servers);
                    if (strpos($flag, $class->flag) !== false) {
                        die($class->handle());
                    }
                }
            }
            $class = new General($user, $servers);
            die($class->handle());
        }
    }

    private function setSubscribeInfoToServers(&$servers, $user, $result = '0.0.0.0', $userip = '0.0.0.0')
    {
        if (!isset($servers[0]))
            return;
        if (!(int) config('v2board.show_info_to_server_enable', 0))
            return;
        $useTraffic = $user['u'] + $user['d'];
        $totalTraffic = $user['transfer_enable'];
        $remainingTraffic = Helper::trafficConvert($totalTraffic - $useTraffic);
        $expiredDate = $user['expired_at'] ? date('Y-m-d', $user['expired_at']) : '长期有效';
        $userService = new UserService();
        $resetDay = $userService->getResetDay($user);
        array_unshift($servers, array_merge($servers[0], [
            'name' => "套餐到期：{$expiredDate}",
        ]));
        if ($resetDay) {
            array_unshift($servers, array_merge($servers[0], [
                'name' => "距离下次重置剩余：{$resetDay} 天",
            ]));
        }
        array_unshift($servers, array_merge($servers[0], [
            'name' => "剩余流量：{$remainingTraffic}",
        ]));
        array_unshift($servers, array_merge($servers[0], [
            'name' => "你的ISP：{$result}",
        ]));
        array_unshift($servers, array_merge($servers[0], [
            'name' => "本次更新ip：{$userip}",
        ]));
    }
}