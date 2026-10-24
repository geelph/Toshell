package config

import (
	"os"
	"testing"
)

// TestMain 在所有用例之前关闭配置热更新监听。
//
// 原因：viper 的 WatchConfig 是**进程级**状态，而本包的用例各自 Load 一个临时配置
// 文件；上一个用例留下的 watcher 会在下一个用例写入/删除临时文件时触发 Reload，
// 打乱后者的断言。CI 上表现为偶发失败
// （TestReloadRejectsBrokenYAMLAndKeepsOldConfig: 重载失败后配置被改动了）。
//
// 这里只影响测试进程，生产路径的 WatchConfig 不受影响。
func TestMain(m *testing.M) {
	DisableWatchForTests()
	os.Exit(m.Run())
}
