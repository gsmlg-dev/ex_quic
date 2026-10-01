defmodule SSL.Test.Compatibility do
  @moduledoc false

  @implementations [otp: :ssl, ex_ssl: SSL]

  @spec implementations() :: [{:otp | :ex_ssl, module()}]
  def implementations, do: @implementations
end
