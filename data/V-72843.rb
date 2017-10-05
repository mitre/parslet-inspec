# encoding: utf-8
#
=begin
-----------------
Benchmark: PostgreSQL 9.x Security Technical Implementation Guide
Status: Accepted

This Security Technical Implementation Guide is published as a tool to improve
the security of Department of Defense (DoD) information systems. The
requirements are derived from the National Institute of Standards and
Technology (NIST) 800-53 and related documents. Comments or proposed revisions
to this document should be sent via email to the following address:
disa.stig_spt@mail.mil.

Release Date: 2017-01-20
Version: 1
Publisher: DISA
Source: STIG.DOD.MIL
uri: http://iase.disa.mil
-----------------
=end
PG_DBA = attribute(
  'pg_dba',
  description: 'The postgres DBA user to access the test database',
  default: 'stig_dba'
)

PG_DBA_PASSWORD = attribute(
  'pg_dba_password',
  description: 'The password for the postgres DBA user',
  default: 'stigD@1234#')

PG_DB = attribute(
  'pg_db',
  description: 'The database used for tests',
  default: 'stig_test_db'
)

PG_HOST = attribute(
  'pg_host',
  description: 'The hostname or IP address used to connect to the database',
  default: '127.0.0.1'
)

control "V-72843" do
  title "PostgreSQL must produce audit records containing sufficient information
  to establish the outcome (success or failure) of the events."
  desc  "Information system auditing capability is critical for accurate
  forensic analysis. Without information about the outcome of events, security
  personnel cannot make an accurate assessment as to whether an attack was
  successful or if changes were made to the security state of the system.
  Event outcomes can include indicators of event success or failure and
  event-specific results (e.g., the security state of the information system
  after the event occurred). As such, they also provide a means to measure the
  impact of an event and help authorized personnel to determine the appropriate
  response."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000099-DB-000043"
  tag "gid": "V-72843"
  tag "rid": "SV-87495r1_rule"
  tag "stig_id": "PGS9-00-000200"
  tag "cci": "CCI-000134"
  tag "nist": ["AU-3", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.

    As a database administrator (shown here as \"postgres\"), create a table,
    insert a value, alter the table and update the table by running the following
    SQL:

    CREATE TABLE stig_test_table(id INT);
    INSERT INTO stig_test_table(id) VALUES (0);
    ALTER TABLE stig_test_table ADD COLUMN name text;
    UPDATE stig_test_table SET id = 1 WHERE id = 0;

    Next, as a user without access to the stig_test table, run the following SQL:

    INSERT INTO stig_test_table(id) VALUES (1);
    ALTER TABLE stig_test_table DROP COLUMN name;
    UPDATE stig_test_table SET id = 0 WHERE id = 1;

    The prior SQL should generate errors:

    'error' => permission denied for relation stig_test
    'error' => must be owner of relation stig_test
    'error' => permission denied for relation stig_test

    Now, as the database administrator, drop the test table by running the
    following SQL:

    DROP TABLE stig_test_table;

    Now verify the errors were logged:

    $ sudo su - postgres
    $ cat ${PGDATA?}/pg_log/<latest_logfile>$PGDATA/
    < 2016-02-23 14:51:31.103 EDT psql postgres postgres 570bf22a.3af2 2016-04-11
    14:51:22 EDT [local] >LOG: AUDIT: SESSION,1,1,DDL,CREATE TABLE,,,CREATE TABLE
    stig_test(id INT);,<none> < 2016-02-23 14:51:44.835 EDT psql postgres
    postgres 570bf22a.3af2 2016-04-11 14:51:22 EDT [local] >LOG: AUDIT:
    SESSION,2,1,WRITE,INSERT,,,INSERT INTO stig_test(id) VALUES (0);,<none>
    < 2016-02-23 14:53:25.805 EDT psql postgres postgres 570bf22a.3af2 2016-04-11
    14:51:22 EDT [local] >LOG: AUDIT: SESSION,3,1,DDL,ALTER TABLE,,,ALTER TABLE
    stig_test ADD COLUMN name text;,<none> < 2016-02-23 14:53:54.381 EDT psql
    postgres postgres 570bf22a.3af2 2016-04-11 14:51:22 EDT [local] >LOG: AUDIT:
    SESSION,4,1,WRITE,UPDATE,,,UPDATE stig_test SET id = 1 WHERE id = 0;,<none>
    < 2016-02-23 14:54:20.832 EDT psql postgres postgres 570bf22a.3af2 2016-04-11
    14:51:22 EDT [local] >'error' => permission denied for relation stig_test
    < 2016-02-23 14:54:20.832 EDT psql postgres postgres 570bf22a.3af2 2016-04-11
    14:51:22 EDT [local] >'statement' => INSERT INTO stig_test(id) VALUES (1);
    < 2016-02-23 14:54:41.032 EDT psql postgres postgres 570bf22a.3af2 2016-04-11
    14:51:22 EDT [local] >'error' => must be owner of relation stig_test < 2016-02-23
    14:54:41.032 EDT psql postgres postgres 570bf22a.3af2 2016-04-11 14:51:22 EDT
    [local] >'statement' => ALTER TABLE stig_test DROP COLUMN name; < 2016-02-23
    14:54:54.378 EDT psql postgres postgres 570bf22a.3af2 2016-04-11 14:51:22 EDT
    [local] >'error' => permission denied for relation stig_test < 2016-02-23
    14:54:54.378 EDT psql postgres postgres 570bf22a.3af2 2016-04-11 14:51:22 EDT
    [local] >'statement' => UPDATE stig_test SET id = 0 WHERE id = 1; < 2016-02-23
    14:55:23.723 EDT psql postgres postgres 570bf307.3b0a 2016-04-11 14:55:03 EDT
    [local] >LOG: AUDIT: SESSION,1,1,DDL,DROP TABLE,,,DROP TABLE stig_test;,<none>

    If audit records exist without the outcome of the event that occurred, this is
    a finding."

    tag "fix": "Using pgaudit PostgreSQL can be configured to audit various facets
    of PostgreSQL. See supplementary content APPENDIX-B for documentation on
    installing pgaudit.
    All errors, denials and unsuccessful requests are logged if logging is enabled.
    See supplementary content APPENDIX-C for documentation on enabling logging.
    Note: The following instructions use the PGDATA environment variable. See
    supplementary content APPENDIX-F for instructions on configuring PGDATA.
    With pgaudit and logging enabled, set the following configuration settings in
    postgresql.conf, as the database administrator (shown here as \"postgres\"),
    to the following:

    $ vi ${PGDATA?}/postgresql.conf
    pgaudit.log_catalog='on'
    pgaudit.log_level='log'
    pgaudit.log_parameter='on'
    pgaudit.log_statement_once='off'
    pgaudit.log='all, -misc'

    Next, tune the following logging configurations in postgresql.conf:

    $ sudo vi ${PGDATA?}/postgresql.conf
    log_line_prefix = '%m %u %d %e : '
    log_error_verbosity = default

    Last, as the system administrator, restart PostgreSQL:

    # SERVER USING SYSTEMCTL ONLY
    $ sudo systemctl restart postgresql-9.5

    # SERVER USING INITD ONLY
    $ sudo service postgresql-9.5 restart"

  # setup/teardown sql commands
  create_role = 'CREATE ROLE joe;'
  set_role = 'SET ROLE joe;'
  drop_role = 'DROP ROLE joe;'

  # test commands and output
  events = [
    {
      'statement' => 'CREATE TABLE stig_test(id INT);',
      'category' => 'DDL'
    },
    {
      'statement' => 'INSERT INTO stig_test(id) VALUES (0);',
      'category' => 'WRITE'
    },
    {
      'statement' => 'ALTER TABLE stig_test ADD COLUMN name text;',
      'category' => 'DDL'
    },
    {
      'statement' => 'UPDATE stig_test SET id = 1 WHERE id = 0;',
      'category' => 'WRITE'
    },
    {
      'statement' => "#{set_role} INSERT INTO stig_test(id) VALUES (1);",
      'category' => 'WRITE',
      'error' => 'permission denied for relation stig_test'
    },
    {
      'statement' => "#{set_role} ALTER TABLE stig_test DROP COLUMN name;",
      'category' => 'DDL',
      'error' => 'must be owner of relation stig_test'
    },
    {
      'statement' => "#{set_role} UPDATE stig_test SET id = 0 WHERE id = 1;",
      'category' => 'WRITE',
      'error' => 'permission denied for relation stig_test'
    },
    {
      'statement' => 'DROP TABLE stig_test;',
      'category' => 'DDL'
    }
  ]

  sql = postgres_session(PG_DBA, PG_DBA_PASSWORD, PG_HOST)
  log_directory_query = sql.query('SHOW log_directory;', [PG_DB])
  log_directory = log_directory_query.output
  current_log_command = "ls -1t #{log_directory}/postgresql-*.log | head -1"
  current_log = command(current_log_command).stdout.strip
  control = File.basename(__FILE__, File.extname(__FILE__))
  message = "starting tests for #{control}"
  message_sql = "DO language plpgsql $$ BEGIN "\
    "RAISE LOG '#{message}'; END $$;"
  start = Time.now.strftime('%Y-%m-%d %H:%M')
  get_logs = "sed -nre '/#{start}.*LOG:\\s+#{message}/,$p' #{current_log}"

  sql.query(message_sql, [PG_DB])
  sql.query(create_role, [PG_DB])

  events.each do |event|
    statement = event['statement']
    category = event['category']
    error = event['error']
    command = statement.match('^([A-Z]+)(\s+)((?!INTO)[A-Z]+)?').to_s.strip
    output = Regexp.new("^#{command}")
    statement_message = Regexp.new("STATEMENT:\\s*#{Regexp.escape(statement)}")
    error_message = Regexp.new("ERROR:\\s*#{error}")
    audit_message = Regexp.new("LOG:\\s*AUDIT:\\s*SESSION(,[\\d]+){2},"\
    "#{category},#{command}(,.*){2},#{Regexp.escape(statement)}")

    describe sql.query(statement, [PG_DB]) do
      if error
        it { should match error_message }
      else
        its('output') { should match output }
      end
    end

    describe command(get_logs) do
      if error
        its('stdout') { should match statement_message }
        its('stdout') { should match error_message }
      else
        its('stdout') { should match audit_message}
      end
    end
  end

  sql.query(drop_role, [PG_DB])

end
