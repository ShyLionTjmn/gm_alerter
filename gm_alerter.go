package main

import (
  "fmt"
  "os"
  "log"
  "time"
  "syscall"
  "os/signal"
  "errors"
  "strings"
  "regexp"
  "strconv"
  "encoding/json"
  "flag"

  "github.com/gomodule/redigo/redis"
  "github.com/marcsauter/single"

  w "github.com/jimlawless/whereami"
  // "github.com/davecgh/go-spew/spew"
  "github.com/fatih/color"

  . "github.com/ShyLionTjmn/aux"
  . "github.com/ShyLionTjmn/gomapper_aux"
)

const CONFIG_CHECK_INTERVAL=60

const SMS_QUEUE="/var/smsqueue"
const MAIL_QUEUE="/var/mymapper/mail_queue"

const ERROR_SLEEP= 10
const NORMAL_SLEEP= 1

const REDIS_SOCKET="/tmp/redis.sock"
const REDIS_DB="0"

var red_db string=REDIS_DB

//var globalMutex = &sync.RWMutex{}
//locks this maps:
var data = make(M)
var opt_v int
var opt_1 bool
var opt_m bool
var opt_s bool
var opt_q bool
var opt_i int

const NO_i_opt = int(1000000000)

var phone_regex *regexp.Regexp

func init() {

  phone_regex = regexp.MustCompile(`^9\d{9}$`)

  w.WhereAmI()
  errors.New("")
  strconv.Itoa(0)
  color.Unset()

  flag.IntVar(&opt_v, "v", 0, "set verbosity level")
  flag.BoolVar(&opt_1, "1", false, "run once, for debugging or running from cron, default if -q not set")
  flag.BoolVar(&opt_m, "m", false, "send mail, use in production")
  flag.BoolVar(&opt_s, "s", false, "send SMS, use in production")
  flag.BoolVar(&opt_q, "q", false, "consume alert queue, use in production")
  flag.IntVar(&opt_i, "i", NO_i_opt, "process alert with redis index (0 = oldest, 1 = second oldest, -1 = most recent, -2 = second recent, etc) , implies -1, can combine with -q")

  flag.Parse()

  if !opt_q { opt_1 = true }

  if opt_i != NO_i_opt { opt_1 = true }
}

func parseConfig(redmap map[string]string) (ret M, ret_err error) {
  ret = make(M)

  alert_keys := make([]string, 0)

  defer func() {
    r := recover()
    if r != nil {
      ret = nil
      ret_err = errors.New("JSON config structure error")
    }
  } ()

  for key, val := range redmap {
    dotpos := strings.Index(key, ".")
    if dotpos > 0 && key[:dotpos] == "rule" && len(key[dotpos+1:]) > 0 {
      ak, err := ParseAlertRule(val)
      if err != nil { return nil, err }
      ret.MkM("rules")[ key[dotpos+1:] ] = val

      for _, k := range ak {
        if IndexOf(alert_keys, k) < 0 {
          alert_keys = append(alert_keys, k)
        }
      }
    } else if dotpos > 0 && key[:dotpos] == "group" && len(key[dotpos+1:]) > 0 {
      ak, err := ParseAlertRule(val)
      if err != nil { return nil, err }
      ret.MkM("group_rules")[ key[dotpos+1:] ] = val
      for _, k := range ak {
        if IndexOf(alert_keys, k) < 0 {
          alert_keys = append(alert_keys, k)
        }
      }
    } else if key == "time" {
      //skip
    } else if key == "config" {
      var j interface{}
      err := json.Unmarshal([]byte(val), &j)
      if err != nil { return nil, err }

      root := j.(map[string]interface{})

      for l0_key, l0_i := range root {
        l0_map := l0_i.(map[string]interface{})
        for l1_key, l1_i := range l0_map {
          if l1_key == "persons" {
            l1_map := l1_i.(map[string]interface{})
            for l2_key, l2_i := range l1_map {
              l2_map := l2_i.(map[string]interface{})
              if v, ok := l2_map["email"]; ok { ret.MkM("user_groups", l0_key, l1_key /*persons*/, l2_key /*userid*/)["email"] = v.(string) }
              if v, ok := l2_map["phone"]; ok { ret.MkM("user_groups", l0_key, l1_key /*persons*/, l2_key /*userid*/)["phone"] = v.(string) }
              if v, ok := l2_map["name"]; ok { ret.MkM("user_groups", l0_key, l1_key /*persons*/, l2_key /*userid*/)["name"] = v.(string) }
            }
          } else if l1_key == "sms_alerts" || l1_key == "mail_alerts" {
            l1_slice := l1_i.([]interface{})
            ret.MkM("user_groups", l0_key)[l1_key] = make([]M, 0)
            for _, l2_i := range l1_slice {
              l2_map := l2_i.(map[string]interface{})
              g, g_ok := l2_map["group"]
              r, r_ok := l2_map["rule"]
              a, a_ok := l2_map["action"]
              if g_ok && r_ok {
                ag := make(M)
                ag["group"] = g.(string)
                ag["rule"] = r.(string)
                if a_ok { ag["action"] = a.(string) }
                ret.MkM("user_groups", l0_key)[l1_key] = append(ret.MkM("user_groups", l0_key)[l1_key].([]M), ag)
              } else {
                return nil, errors.New("Incomplete JSON alerts key "+l0_key+"->"+l1_key)
              }
            }
          } else {
            return nil, errors.New("Unknown JSON config key "+l1_key)
          }
        }
      }
    } else {
      return nil, errors.New("Unknown config key "+key)
    }
  }

  if !ret.EvM("user_groups") { return nil, errors.New("No user groups defined in JSON") }
  //check if mentioned groups and rules exists
  for _, ug_i := range ret.VM("user_groups") {
    ug_h := ug_i.(M)
    if ag_i, ok := ug_h.VAe("sms_alerts"); ok {
      ag_s := ag_i.([]M)
      for _, ag_h := range ag_s {
        if ag_h.Vs("group") != "*" && !ret.Evs("group_rules", ag_h.Vs("group")) {
          return nil, errors.New("Reference to unknown group rule "+ag_h.Vs("group"))
        }
        if !ret.Evs("rules", ag_h.Vs("rule")) {
          return nil, errors.New("Reference to unknown rule "+ag_h.Vs("rule"))
        }
      }
    }
    if ag_i, ok := ug_h.VAe("mail_alerts"); ok {
      ag_s := ag_i.([]M)
      for _, ag_h := range ag_s {
        if ag_h.Vs("group") != "*" && !ret.Evs("group_rules", ag_h.Vs("group")) {
          return nil, errors.New("Reference to unknown group rule "+ag_h.Vs("group"))
        }
        if !ret.Evs("rules", ag_h.Vs("rule")) {
          return nil, errors.New("Reference to unknown rule "+ag_h.Vs("rule"))
        }
      }
    }
  }

  ret["alert_keys"] = alert_keys

  return ret, nil
}

func mailAlert(emails []string, a map[string]string) {
  defer func() {
    recover() //just ignore type assertions
  } ()

  var subj string

  var body string

  if a["alert_type"] == "dev" {
    if a["alert_key"] == "overall_status" {
      subj = strings.ToUpper(a["overall_status"])+": status "+a["short_name"]+" ("+a["sysLocation"]+")"
      body = "Status "+strings.ToUpper(a["overall_status"])
    } else if a["alert_key"] == "powerState" {
      if a["new"] != "1" {
        subj = "CRIT: power"
        body = "Power FAILED"
      } else {
        subj = "OK: power"
        body = "Power restored"
      }
    } else {
      subj = a["alert_key"]+": "+a["new"]
      body = a["alert_key"]+": "+a["new"]+"\nPrev: "+a["old"]
    }
  } else if a["alert_type"] == "int" {
    if a["alert_key"] == "ifOperStatus" {
      if a["new"] == "1" {
        subj = "OK: ifUp"
        body = "UP"
      } else if a["new"] == "2" {
        subj = "CRIT: ifDown"
        body = "DOWN"
      }
    } else {
      subj = a["alert_key"]+": "+a["new"]
      body = a["alert_key"]+": "+a["new"]+"\nPrev: "+a["old"]
    }
    subj += " "+a["ifName"]
    body += "\nInterface: "+a["ifName"]
    if a["ifAlias"] != "" {
      subj += " ("+a["ifAlias"]+")"
      body += " ("+a["ifAlias"]+")"
    }
  }
  subj += " @ "+a["short_name"]+" ("+a["sysLocation"]+")"
  body += "\nDevice: "+a["short_name"]+" ("+a["sysLocation"]+")"
  body += "\nDevID: "+a["id"]+" ("+a["data_ip"]+")"
  i, err := strconv.ParseInt(a["last_seen"], 10, 64)
  if err == nil {
    body += "\nLastSeen: "+time.Unix(i, 0).Format("Mon, 2006 Jan 2 15:04:05 ")
  }
  i, err = strconv.ParseInt(a["time"], 10, 64)
  if err == nil {
    body += "\nTimestamp: "+time.Unix(i, 0).Format("Mon, 2006 Jan 2 15:04:05 ")
  }

  if opt_v > 1 {
    fmt.Println()
    fmt.Println(emails)
    fmt.Println("Mail:", subj)
    fmt.Println(body)
  }
  if opt_m {
    if _, e := os.Stat(MAIL_QUEUE+"/pause"); e != nil && os.IsNotExist(e) {
      for _, email := range emails {
        file_name_prefix := MAIL_QUEUE+"/mail."
        suffix_i := time.Now().UnixNano()
        var fd *os.File
        var err error
        for {
          file_name := file_name_prefix+strconv.FormatInt(suffix_i, 10)
          fd, err = os.OpenFile(file_name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
          if err != nil && os.IsExist(err) {
            suffix_i++
          } else {
            break
          }
        }
        if err != nil {
          if opt_v > 0 {
            fmt.Println(err.Error())
          }
          return
        }
        fmt.Fprintln(fd, email)
        fmt.Fprintln(fd, subj)
        fmt.Fprintln(fd, body)
        fd.Close()
      }
    }
  }
}

func smsAlert(phones []string, a map[string]string) {
  defer func() {
    recover() //just ignore type assertions
  } ()

  var text string

  if a["alert_type"] == "dev" {
    if a["alert_key"] == "overall_status" {
      text = strings.ToUpper(a["overall_status"])+": status"
    } else if a["alert_key"] == "powerState" {
      if a["new"] != "1" {
        text = "CRIT: power"
      } else {
        text = "OK: power"
      }
    } else {
      text = a["alert_key"]+": "+a["new"]
    }
  } else if a["alert_type"] == "int" {
    if a["alert_key"] == "ifOperStatus" {
      if a["new"] == "1" {
        text = "OK: ifUp"
      } else if a["new"] == "2" {
        text = "CRIT: ifDown"
      }
    } else {
      text = a["alert_key"]+": "+a["new"]
    }
    text += " "+a["ifName"]
    if a["ifAlias"] != "" {
      text += " ("+a["ifAlias"]+")"
    }
  }
  text += " @ "+a["short_name"]+" ("+a["sysLocation"]+")"

  if opt_v > 1 {
    fmt.Println()
    fmt.Println(phones)
    fmt.Println("SMS:", text)
  }
  if opt_s {
    if _, e := os.Stat(SMS_QUEUE+"/pause"); e != nil && os.IsNotExist(e) {
      for _, phone := range phones {
        if phone_regex.MatchString(phone) {
          file_name_prefix := SMS_QUEUE+"/"+phone+"."
          suffix_i := time.Now().UnixNano()
          var fd *os.File
          var err error
          for {
            file_name := file_name_prefix+strconv.FormatInt(suffix_i, 10)
            fd, err = os.OpenFile(file_name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
            if err != nil && os.IsExist(err) {
              suffix_i++
            } else {
              break
            }
          }
          if err != nil {
            if opt_v > 0 {
              fmt.Println(err.Error())
            }
            return
          }
          fmt.Fprintln(fd, text)
          fd.Close()
        }
      }
    }
  }
}

func processAlert(alert_json string) error {
  defer func() {
    recover() //just ignore type assertions
  } ()

  var a map[string]string

  jerr := json.Unmarshal([]byte(alert_json), &a)
  if jerr != nil { return jerr }

  if opt_v > 3 {
    j, _ := json.MarshalIndent(a, "       ", "  ")
    fmt.Println()
    fmt.Println("Alert:", string(j))
  }

  //skip pausing or adding new devs
  if a["alert_type"] == "dev" && a["alert_key"] == "overall_status" {
    if (a["new"] == "ok" && a["old"] == "") ||
       (a["new"] == "ok" && a["old"] == "paused") ||
       (a["new"] == "paused")  ||
       false {
      //if
      if opt_v > 1 {
        fmt.Println()
        fmt.Println("Ignore: "+a["alert_type"]+" "+a["ifName"]+" @ "+a["short_name"]+" "+a["alert_key"]+" "+a["old"]+" -> "+a["new"]+" time: "+a["time"])
      }
      return nil
    }
  } else if a["alert_type"] == "int" && a["overall_status"] != "ok" {
    //skip changes with not running devices
    if opt_v > 1 {
      fmt.Println()
      fmt.Println("Ignore: "+a["alert_type"]+" "+a["ifName"]+" @ "+a["short_name"]+" "+a["alert_key"]+" "+a["old"]+" -> "+a["new"]+" time: "+a["time"])
    }
    return nil
  }

  host_groups := make([]string, 0)
  alert_emails := make([]string, 0)
  alert_phones := make([]string, 0)

  if group_rules, ok := data.VMe("config", "group_rules"); ok {
    for group, rule_i := range group_rules {
      match, err := MatchAlertRule(rule_i.(string), a)
//fmt.Println(match, rule_i.(string))
      if err == nil && match {
        host_groups = append(host_groups, group)
      }
    }
  }

  if user_groups, ok := data.VMe("config", "user_groups"); ok {
    for ug_id, ug_m := range user_groups {
      ug_h := ug_m.(M)
      if persons_h, ok := ug_h.VMe("persons"); ok {
        emails := make([]string, 0)
        phones := make([]string, 0)

        for _, p_m := range persons_h {
          if email, ok := p_m.(M).Vse("email"); ok && IndexOf(emails, email) < 0 {
            emails = append(emails, email)
          }
          if phone, ok := p_m.(M).Vse("phone"); ok && IndexOf(phones, phone) < 0 {
            phones = append(phones, phone)
          }
        }

        if ags_i, ok := data.VAe("config", "user_groups", ug_id, "mail_alerts"); ok && len(emails) > 0 {
          for _, ag_h := range ags_i.([]M) {
            if ag_h.Vs("action") != "ignore" {
              if rule, ok := data.Vse("config", "rules", ag_h.Vs("rule")); ok && (ag_h.Vs("group") == "*" || IndexOf(host_groups, ag_h.Vs("group")) >= 0) {
                match, err := MatchAlertRule(rule, a)
                if match && err == nil {
                  if opt_v > 2 {
                    fmt.Println("Matched:", ug_id, "mail_alerts", ag_h.Vs("group"), ag_h.Vs("rule"))
                  }
                  for _, email := range emails {
                    alert_emails = StrAppendOnce(alert_emails, email)
                  }
                }
                if ag_h.Vs("action") == "stop" {
                  break
                }
              }
            }
          }
        }
        if ags_i, ok := data.VAe("config", "user_groups", ug_id, "sms_alerts"); ok && len(phones) > 0 {
          for _, ag_h := range ags_i.([]M) {
            if ag_h.Vs("action") != "ignore" {
              if rule, ok := data.Vse("config", "rules", ag_h.Vs("rule")); ok && (ag_h.Vs("group") == "*" || IndexOf(host_groups, ag_h.Vs("group")) >= 0) {
                match, err := MatchAlertRule(rule, a)
                if match && err == nil {
                  if opt_v > 2 {
                    fmt.Println("Matched:", ug_id, "sms_alerts", ag_h.Vs("group"), ag_h.Vs("rule"))
                  }
                  for _, phone := range phones {
                    alert_phones = StrAppendOnce(alert_phones, phone)
                  }
                }
                if ag_h.Vs("action") == "stop" {
                  break
                }
              }
            }
          }
        }
      }
    }
  }

  if len(alert_phones) > 0 { smsAlert(alert_phones, a) }
  if len(alert_emails) > 0 { mailAlert(alert_emails, a) }

  if len(alert_phones) == 0 && len(alert_emails) == 0 {
    if opt_v > 1 {
      fmt.Println()
      fmt.Println("Ignore: "+a["alert_type"]+" "+a["ifName"]+" @ "+a["short_name"]+" "+a["alert_key"]+" "+a["old"]+" -> "+a["new"]+" time: "+a["time"])
    }
  }
  return nil
}

func main() {

  var err error

  single_run := single.New("gm_alerter."+red_db) // add redis_db here later

  if err = single_run.CheckLock(); err != nil && err == single.ErrAlreadyRunning {
    log.Fatal("another instance of the app is already running, exiting")
  } else if err != nil {
    // Another error occurred, might be worth handling it as well
    log.Fatalf("failed to acquire exclusive app lock: %v", err)
  }
  defer single_run.TryUnlock()

  sig_ch := make(chan os.Signal, 1)
  signal.Notify(sig_ch, syscall.SIGHUP)
  signal.Notify(sig_ch, syscall.SIGINT)
  signal.Notify(sig_ch, syscall.SIGTERM)
  signal.Notify(sig_ch, syscall.SIGQUIT)


  var red redis.Conn

  var config_check_time int64
  var config_time string

  defer func() { if red != nil { red.Close() } } ()

  configState := NewSomeState("config")
  redState := NewSomeState("redis")

MAIN_LOOP:
  for {

    red, err = RedisCheck(red, "unix", REDIS_SOCKET, red_db)

    redState.State(red != nil && err == nil, err)

    if red != nil && (config_check_time + CONFIG_CHECK_INTERVAL) < time.Now().Unix() {
      config_check_time = time.Now().Unix()
      var redstr string
      redstr, err = redis.String(red.Do("HGET", "alert_config", "time"))
      if err == nil && redstr != config_time {
        var redmap map[string]string
        redmap, err = redis.StringMap(red.Do("HGETALL", "alert_config"))
        if err == nil {
          var config M
          config, err = parseConfig(redmap)
          if err == nil {
            data["config"] = config
            config_time = redstr
          }
        }
      } else if err == redis.ErrNil {
        err = errors.New("alert_config or its time is missing")
      }
      configState.State(err == nil, err)
    }

    if red != nil && config_time != "" {
      var queue_len int
      queue_len, err = redis.Int(red.Do("LLEN", "alert"))
      if err == nil && queue_len > 0 {
        var alert_json string

        if opt_i != NO_i_opt {
          alert_json, err = redis.String(red.Do("LINDEX", "alert", opt_i))
          if err == nil {
            err = processAlert(alert_json)
            if err == nil && opt_q {
              _, err = red.Do("LSET", "alert", opt_i, "DELETE")
              if err == nil {
                _, err = red.Do("LREM", "alert", 0, "DELETE")
              }
            }
          }
        } else if !opt_q {
          for i := 0; i < queue_len; i++ {
            alert_json, err = redis.String(red.Do("LINDEX", "alert", i))
            if err != nil { break }

            err = processAlert(alert_json)
            if err != nil { break }
          }
        } else {
          for alert_json, err = redis.String(red.Do("LPOP", "alert")); err == nil; alert_json, err = redis.String(red.Do("LPOP", "alert")) {
            err = processAlert(alert_json)
            if err != nil { break }
          }
        }
      }
      if err != nil && err != redis.ErrNil {
        if opt_v > 0 {
          fmt.Println(err)
        }
      } else if err == redis.ErrNil {
        err = nil
      }
    }

    if opt_1 { break MAIN_LOOP }

    sleep_time := time.Duration(NORMAL_SLEEP)*time.Second
    if err != nil { sleep_time = time.Duration(ERROR_SLEEP)*time.Second }

    if opt_v > 6 {
      fmt.Println("Sleep", sleep_time, "seconds")
    }

    main_timer := time.NewTimer(sleep_time)

    select {
    case s := <-sig_ch:
      main_timer.Stop()
      if opt_v > 0 {
        fmt.Println("\nmain got signal")
      }
      if s != syscall.SIGHUP && s != syscall.SIGUSR1 {
        break MAIN_LOOP
      }
      continue MAIN_LOOP
    case <- main_timer.C:
      continue MAIN_LOOP
    }
  } //MAIN_LOOP


  if !opt_1 {
    fmt.Println("main done")
  }
}
